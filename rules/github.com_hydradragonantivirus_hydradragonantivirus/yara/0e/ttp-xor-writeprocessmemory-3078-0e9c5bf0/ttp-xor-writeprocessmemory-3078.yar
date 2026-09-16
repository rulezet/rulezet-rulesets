rule TTP_XOR_WriteProcessMemory_3078 {
  strings:
    $key_3078 = { 67 0a [2] 55 28 [2] 53 1d [2] 7d 1d [2] 42 01 }

  condition:
    any of them
}