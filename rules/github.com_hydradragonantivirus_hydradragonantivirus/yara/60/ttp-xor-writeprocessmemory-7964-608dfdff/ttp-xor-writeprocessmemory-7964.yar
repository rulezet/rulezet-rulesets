rule TTP_XOR_WriteProcessMemory_7964 {
  strings:
    $key_7964 = { 2e 16 [2] 1c 34 [2] 1a 01 [2] 34 01 [2] 0b 1d }

  condition:
    any of them
}