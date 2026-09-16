rule TTP_XOR_WriteProcessMemory_0af8 {
  strings:
    $key_0af8 = { 5d 8a [2] 6f a8 [2] 69 9d [2] 47 9d [2] 78 81 }

  condition:
    any of them
}