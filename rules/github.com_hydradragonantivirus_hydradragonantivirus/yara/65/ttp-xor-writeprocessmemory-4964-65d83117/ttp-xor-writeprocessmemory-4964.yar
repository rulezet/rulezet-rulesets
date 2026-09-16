rule TTP_XOR_WriteProcessMemory_4964 {
  strings:
    $key_4964 = { 1e 16 [2] 2c 34 [2] 2a 01 [2] 04 01 [2] 3b 1d }

  condition:
    any of them
}