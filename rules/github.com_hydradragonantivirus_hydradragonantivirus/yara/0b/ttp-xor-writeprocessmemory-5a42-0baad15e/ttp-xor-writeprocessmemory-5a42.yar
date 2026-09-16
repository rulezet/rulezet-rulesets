rule TTP_XOR_WriteProcessMemory_5a42 {
  strings:
    $key_5a42 = { 0d 30 [2] 3f 12 [2] 39 27 [2] 17 27 [2] 28 3b }

  condition:
    any of them
}