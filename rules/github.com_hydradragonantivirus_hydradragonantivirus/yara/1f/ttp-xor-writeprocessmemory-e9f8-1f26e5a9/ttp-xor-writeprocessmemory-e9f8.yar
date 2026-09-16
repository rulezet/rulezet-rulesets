rule TTP_XOR_WriteProcessMemory_e9f8 {
  strings:
    $key_e9f8 = { be 8a [2] 8c a8 [2] 8a 9d [2] a4 9d [2] 9b 81 }

  condition:
    any of them
}