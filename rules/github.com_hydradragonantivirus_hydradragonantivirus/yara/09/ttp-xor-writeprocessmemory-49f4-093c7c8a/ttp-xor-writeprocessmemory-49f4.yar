rule TTP_XOR_WriteProcessMemory_49f4 {
  strings:
    $key_49f4 = { 1e 86 [2] 2c a4 [2] 2a 91 [2] 04 91 [2] 3b 8d }

  condition:
    any of them
}