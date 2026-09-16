rule TTP_XOR_WriteProcessMemory_ace4 {
  strings:
    $key_ace4 = { fb 96 [2] c9 b4 [2] cf 81 [2] e1 81 [2] de 9d }

  condition:
    any of them
}