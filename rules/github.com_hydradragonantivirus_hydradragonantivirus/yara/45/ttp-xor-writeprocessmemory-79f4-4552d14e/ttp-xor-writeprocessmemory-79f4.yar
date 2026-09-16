rule TTP_XOR_WriteProcessMemory_79f4 {
  strings:
    $key_79f4 = { 2e 86 [2] 1c a4 [2] 1a 91 [2] 34 91 [2] 0b 8d }

  condition:
    any of them
}