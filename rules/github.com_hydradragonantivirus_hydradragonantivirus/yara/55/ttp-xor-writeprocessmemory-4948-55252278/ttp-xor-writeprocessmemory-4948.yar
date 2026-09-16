rule TTP_XOR_WriteProcessMemory_4948 {
  strings:
    $key_4948 = { 1e 3a [2] 2c 18 [2] 2a 2d [2] 04 2d [2] 3b 31 }

  condition:
    any of them
}