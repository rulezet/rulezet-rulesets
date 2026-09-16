rule TTP_XOR_WriteProcessMemory_5964 {
  strings:
    $key_5964 = { 0e 16 [2] 3c 34 [2] 3a 01 [2] 14 01 [2] 2b 1d }

  condition:
    any of them
}