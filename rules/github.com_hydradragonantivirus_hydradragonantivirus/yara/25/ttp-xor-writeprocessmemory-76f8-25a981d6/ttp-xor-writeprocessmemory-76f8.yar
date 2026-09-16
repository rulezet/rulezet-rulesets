rule TTP_XOR_WriteProcessMemory_76f8 {
  strings:
    $key_76f8 = { 21 8a [2] 13 a8 [2] 15 9d [2] 3b 9d [2] 04 81 }

  condition:
    any of them
}