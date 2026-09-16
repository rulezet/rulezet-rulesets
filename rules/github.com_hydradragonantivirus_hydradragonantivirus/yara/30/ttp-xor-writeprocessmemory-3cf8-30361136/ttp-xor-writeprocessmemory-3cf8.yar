rule TTP_XOR_WriteProcessMemory_3cf8 {
  strings:
    $key_3cf8 = { 6b 8a [2] 59 a8 [2] 5f 9d [2] 71 9d [2] 4e 81 }

  condition:
    any of them
}