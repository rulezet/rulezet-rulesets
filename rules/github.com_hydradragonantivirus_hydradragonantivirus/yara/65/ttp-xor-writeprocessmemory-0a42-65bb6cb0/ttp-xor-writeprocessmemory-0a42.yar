rule TTP_XOR_WriteProcessMemory_0a42 {
  strings:
    $key_0a42 = { 5d 30 [2] 6f 12 [2] 69 27 [2] 47 27 [2] 78 3b }

  condition:
    any of them
}