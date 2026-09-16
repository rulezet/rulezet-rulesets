rule TTP_XOR_WriteProcessMemory_8654 {
  strings:
    $key_8654 = { d1 26 [2] e3 04 [2] e5 31 [2] cb 31 [2] f4 2d }

  condition:
    any of them
}