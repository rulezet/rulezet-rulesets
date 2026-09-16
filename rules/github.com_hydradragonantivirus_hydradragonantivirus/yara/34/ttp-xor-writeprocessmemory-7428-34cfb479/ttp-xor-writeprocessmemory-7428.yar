rule TTP_XOR_WriteProcessMemory_7428 {
  strings:
    $key_7428 = { 23 5a [2] 11 78 [2] 17 4d [2] 39 4d [2] 06 51 }

  condition:
    any of them
}