rule TTP_XOR_WriteProcessMemory_2078 {
  strings:
    $key_2078 = { 77 0a [2] 45 28 [2] 43 1d [2] 6d 1d [2] 52 01 }

  condition:
    any of them
}