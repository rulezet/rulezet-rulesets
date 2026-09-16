rule TTP_XOR_WriteProcessMemory_4918 {
  strings:
    $key_4918 = { 1e 6a [2] 2c 48 [2] 2a 7d [2] 04 7d [2] 3b 61 }

  condition:
    any of them
}