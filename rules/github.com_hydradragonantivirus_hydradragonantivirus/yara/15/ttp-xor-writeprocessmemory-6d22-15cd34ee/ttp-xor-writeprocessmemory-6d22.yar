rule TTP_XOR_WriteProcessMemory_6d22 {
  strings:
    $key_6d22 = { 3a 50 [2] 08 72 [2] 0e 47 [2] 20 47 [2] 1f 5b }

  condition:
    any of them
}