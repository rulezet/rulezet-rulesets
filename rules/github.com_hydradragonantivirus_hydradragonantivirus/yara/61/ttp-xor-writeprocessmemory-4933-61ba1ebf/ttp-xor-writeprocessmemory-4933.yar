rule TTP_XOR_WriteProcessMemory_4933 {
  strings:
    $key_4933 = { 1e 41 [2] 2c 63 [2] 2a 56 [2] 04 56 [2] 3b 4a }

  condition:
    any of them
}