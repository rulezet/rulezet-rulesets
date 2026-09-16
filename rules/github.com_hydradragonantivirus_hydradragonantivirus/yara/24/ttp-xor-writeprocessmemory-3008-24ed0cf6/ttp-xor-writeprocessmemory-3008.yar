rule TTP_XOR_WriteProcessMemory_3008 {
  strings:
    $key_3008 = { 67 7a [2] 55 58 [2] 53 6d [2] 7d 6d [2] 42 71 }

  condition:
    any of them
}