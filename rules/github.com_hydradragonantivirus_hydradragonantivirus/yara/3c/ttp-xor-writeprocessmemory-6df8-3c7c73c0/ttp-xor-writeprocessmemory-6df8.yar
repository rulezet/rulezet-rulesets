rule TTP_XOR_WriteProcessMemory_6df8 {
  strings:
    $key_6df8 = { 3a 8a [2] 08 a8 [2] 0e 9d [2] 20 9d [2] 1f 81 }

  condition:
    any of them
}