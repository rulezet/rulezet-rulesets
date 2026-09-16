rule TTP_XOR_WriteProcessMemory_6335 {
  strings:
    $key_6335 = { 34 47 [2] 06 65 [2] 00 50 [2] 2e 50 [2] 11 4c }

  condition:
    any of them
}