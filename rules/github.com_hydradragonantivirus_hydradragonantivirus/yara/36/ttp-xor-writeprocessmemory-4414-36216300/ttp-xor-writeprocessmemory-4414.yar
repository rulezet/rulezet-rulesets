rule TTP_XOR_WriteProcessMemory_4414 {
  strings:
    $key_4414 = { 13 66 [2] 21 44 [2] 27 71 [2] 09 71 [2] 36 6d }

  condition:
    any of them
}