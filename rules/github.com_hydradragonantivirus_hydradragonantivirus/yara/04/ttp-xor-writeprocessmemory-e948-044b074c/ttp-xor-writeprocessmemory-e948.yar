rule TTP_XOR_WriteProcessMemory_e948 {
  strings:
    $key_e948 = { be 3a [2] 8c 18 [2] 8a 2d [2] a4 2d [2] 9b 31 }

  condition:
    any of them
}