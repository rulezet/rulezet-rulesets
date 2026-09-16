rule TTP_XOR_WriteProcessMemory_ace1 {
  strings:
    $key_ace1 = { fb 93 [2] c9 b1 [2] cf 84 [2] e1 84 [2] de 98 }

  condition:
    any of them
}