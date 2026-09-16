rule TTP_XOR_WriteProcessMemory_4bf8 {
  strings:
    $key_4bf8 = { 1c 8a [2] 2e a8 [2] 28 9d [2] 06 9d [2] 39 81 }

  condition:
    any of them
}