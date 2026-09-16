rule TTP_XOR_WriteProcessMemory_24f8 {
  strings:
    $key_24f8 = { 73 8a [2] 41 a8 [2] 47 9d [2] 69 9d [2] 56 81 }

  condition:
    any of them
}