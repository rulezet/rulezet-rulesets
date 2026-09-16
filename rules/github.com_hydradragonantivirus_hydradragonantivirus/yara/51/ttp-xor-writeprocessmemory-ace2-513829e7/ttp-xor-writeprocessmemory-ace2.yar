rule TTP_XOR_WriteProcessMemory_ace2 {
  strings:
    $key_ace2 = { fb 90 [2] c9 b2 [2] cf 87 [2] e1 87 [2] de 9b }

  condition:
    any of them
}