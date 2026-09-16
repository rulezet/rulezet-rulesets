rule TTP_XOR_WriteProcessMemory_4a14 {
  strings:
    $key_4a14 = { 1d 66 [2] 2f 44 [2] 29 71 [2] 07 71 [2] 38 6d }

  condition:
    any of them
}