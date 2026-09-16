rule TTP_XOR_WriteProcessMemory_7967 {
  strings:
    $key_7967 = { 2e 15 [2] 1c 37 [2] 1a 02 [2] 34 02 [2] 0b 1e }

  condition:
    any of them
}