rule TTP_XOR_WriteProcessMemory_5a25 {
  strings:
    $key_5a25 = { 0d 57 [2] 3f 75 [2] 39 40 [2] 17 40 [2] 28 5c }

  condition:
    any of them
}