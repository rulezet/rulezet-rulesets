rule TTP_XOR_WriteProcessMemory_7970 {
  strings:
    $key_7970 = { 2e 02 [2] 1c 20 [2] 1a 15 [2] 34 15 [2] 0b 09 }

  condition:
    any of them
}