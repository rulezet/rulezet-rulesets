rule TTP_XOR_WriteProcessMemory_2312 {
  strings:
    $key_2312 = { 74 60 [2] 46 42 [2] 40 77 [2] 6e 77 [2] 51 6b }

  condition:
    any of them
}