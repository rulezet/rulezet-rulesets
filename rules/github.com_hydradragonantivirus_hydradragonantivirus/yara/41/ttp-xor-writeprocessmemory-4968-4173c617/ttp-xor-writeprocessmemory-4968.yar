rule TTP_XOR_WriteProcessMemory_4968 {
  strings:
    $key_4968 = { 1e 1a [2] 2c 38 [2] 2a 0d [2] 04 0d [2] 3b 11 }

  condition:
    any of them
}