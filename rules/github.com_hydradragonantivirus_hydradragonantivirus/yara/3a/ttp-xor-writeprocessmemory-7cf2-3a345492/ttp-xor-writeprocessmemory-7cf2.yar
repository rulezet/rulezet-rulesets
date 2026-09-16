rule TTP_XOR_WriteProcessMemory_7cf2 {
  strings:
    $key_7cf2 = { 2b 80 [2] 19 a2 [2] 1f 97 [2] 31 97 [2] 0e 8b }

  condition:
    any of them
}