rule TTP_XOR_WriteProcessMemory_3af8 {
  strings:
    $key_3af8 = { 6d 8a [2] 5f a8 [2] 59 9d [2] 77 9d [2] 48 81 }

  condition:
    any of them
}