rule TTP_XOR_WriteProcessMemory_4938 {
  strings:
    $key_4938 = { 1e 4a [2] 2c 68 [2] 2a 5d [2] 04 5d [2] 3b 41 }

  condition:
    any of them
}