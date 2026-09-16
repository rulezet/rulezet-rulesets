rule TTP_XOR_WriteProcessMemory_7915 {
  strings:
    $key_7915 = { 2e 67 [2] 1c 45 [2] 1a 70 [2] 34 70 [2] 0b 6c }

  condition:
    any of them
}