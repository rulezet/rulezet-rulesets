rule TTP_XOR_WriteProcessMemory_3756 {
  strings:
    $key_3756 = { 60 24 [2] 52 06 [2] 54 33 [2] 7a 33 [2] 45 2f }

  condition:
    any of them
}