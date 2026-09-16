rule TTP_XOR_WriteProcessMemory_20f8 {
  strings:
    $key_20f8 = { 77 8a [2] 45 a8 [2] 43 9d [2] 6d 9d [2] 52 81 }

  condition:
    any of them
}