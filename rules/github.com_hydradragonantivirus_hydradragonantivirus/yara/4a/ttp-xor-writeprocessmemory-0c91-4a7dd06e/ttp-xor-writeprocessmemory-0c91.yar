rule TTP_XOR_WriteProcessMemory_0c91 {
  strings:
    $key_0c91 = { 5b e3 [2] 69 c1 [2] 6f f4 [2] 41 f4 [2] 7e e8 }

  condition:
    any of them
}