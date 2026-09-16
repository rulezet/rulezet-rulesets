rule TTP_XOR_WriteProcessMemory_ace7 {
  strings:
    $key_ace7 = { fb 95 [2] c9 b7 [2] cf 82 [2] e1 82 [2] de 9e }

  condition:
    any of them
}