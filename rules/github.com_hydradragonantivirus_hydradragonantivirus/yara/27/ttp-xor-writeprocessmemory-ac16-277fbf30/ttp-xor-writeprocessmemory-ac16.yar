rule TTP_XOR_WriteProcessMemory_ac16 {
  strings:
    $key_ac16 = { fb 64 [2] c9 46 [2] cf 73 [2] e1 73 [2] de 6f }

  condition:
    any of them
}