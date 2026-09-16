rule TTP_XOR_WriteProcessMemory_1208 {
  strings:
    $key_1208 = { 45 7a [2] 77 58 [2] 71 6d [2] 5f 6d [2] 60 71 }

  condition:
    any of them
}