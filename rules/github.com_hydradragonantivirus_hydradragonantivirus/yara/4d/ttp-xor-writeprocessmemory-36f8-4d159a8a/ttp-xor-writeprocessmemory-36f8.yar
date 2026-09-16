rule TTP_XOR_WriteProcessMemory_36f8 {
  strings:
    $key_36f8 = { 61 8a [2] 53 a8 [2] 55 9d [2] 7b 9d [2] 44 81 }

  condition:
    any of them
}