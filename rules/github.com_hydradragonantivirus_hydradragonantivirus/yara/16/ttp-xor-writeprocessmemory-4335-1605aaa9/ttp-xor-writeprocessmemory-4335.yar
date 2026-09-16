rule TTP_XOR_WriteProcessMemory_4335 {
  strings:
    $key_4335 = { 14 47 [2] 26 65 [2] 20 50 [2] 0e 50 [2] 31 4c }

  condition:
    any of them
}