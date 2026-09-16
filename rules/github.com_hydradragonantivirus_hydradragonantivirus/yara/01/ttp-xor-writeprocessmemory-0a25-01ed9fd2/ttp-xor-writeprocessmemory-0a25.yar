rule TTP_XOR_WriteProcessMemory_0a25 {
  strings:
    $key_0a25 = { 5d 57 [2] 6f 75 [2] 69 40 [2] 47 40 [2] 78 5c }

  condition:
    any of them
}