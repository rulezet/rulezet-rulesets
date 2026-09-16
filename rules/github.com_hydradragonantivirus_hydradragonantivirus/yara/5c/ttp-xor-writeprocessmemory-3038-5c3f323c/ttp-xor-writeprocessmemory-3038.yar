rule TTP_XOR_WriteProcessMemory_3038 {
  strings:
    $key_3038 = { 67 4a [2] 55 68 [2] 53 5d [2] 7d 5d [2] 42 41 }

  condition:
    any of them
}