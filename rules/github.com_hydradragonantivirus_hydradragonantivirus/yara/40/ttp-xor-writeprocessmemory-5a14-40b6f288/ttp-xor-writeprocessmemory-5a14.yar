rule TTP_XOR_WriteProcessMemory_5a14 {
  strings:
    $key_5a14 = { 0d 66 [2] 3f 44 [2] 39 71 [2] 17 71 [2] 28 6d }

  condition:
    any of them
}