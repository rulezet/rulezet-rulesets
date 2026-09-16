rule TTP_XOR_WriteProcessMemory_7522 {
  strings:
    $key_7522 = { 22 50 [2] 10 72 [2] 16 47 [2] 38 47 [2] 07 5b }

  condition:
    any of them
}