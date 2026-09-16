rule TTP_XOR_WriteProcessMemory_3bf8 {
  strings:
    $key_3bf8 = { 6c 8a [2] 5e a8 [2] 58 9d [2] 76 9d [2] 49 81 }

  condition:
    any of them
}