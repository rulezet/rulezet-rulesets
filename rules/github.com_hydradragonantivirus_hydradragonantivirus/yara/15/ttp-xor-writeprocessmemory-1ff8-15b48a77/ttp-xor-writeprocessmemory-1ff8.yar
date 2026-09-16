rule TTP_XOR_WriteProcessMemory_1ff8 {
  strings:
    $key_1ff8 = { 48 8a [2] 7a a8 [2] 7c 9d [2] 52 9d [2] 6d 81 }

  condition:
    any of them
}