rule TTP_XOR_WriteProcessMemory_7f45 {
  strings:
    $key_7f45 = { 28 37 [2] 1a 15 [2] 1c 20 [2] 32 20 [2] 0d 3c }

  condition:
    any of them
}