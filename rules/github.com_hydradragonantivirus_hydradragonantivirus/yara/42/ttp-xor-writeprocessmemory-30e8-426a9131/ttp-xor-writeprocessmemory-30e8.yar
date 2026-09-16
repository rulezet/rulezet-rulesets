rule TTP_XOR_WriteProcessMemory_30e8 {
  strings:
    $key_30e8 = { 67 9a [2] 55 b8 [2] 53 8d [2] 7d 8d [2] 42 91 }

  condition:
    any of them
}