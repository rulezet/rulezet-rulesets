rule TTP_XOR_WriteProcessMemory_5a03 {
  strings:
    $key_5a03 = { 0d 71 [2] 3f 53 [2] 39 66 [2] 17 66 [2] 28 7a }

  condition:
    any of them
}