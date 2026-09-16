rule TTP_XOR_WriteProcessMemory_48f8 {
  strings:
    $key_48f8 = { 1f 8a [2] 2d a8 [2] 2b 9d [2] 05 9d [2] 3a 81 }

  condition:
    any of them
}