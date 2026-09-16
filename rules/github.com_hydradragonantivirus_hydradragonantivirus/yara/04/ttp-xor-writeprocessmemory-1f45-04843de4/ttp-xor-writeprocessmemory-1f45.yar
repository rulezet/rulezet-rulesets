rule TTP_XOR_WriteProcessMemory_1f45 {
  strings:
    $key_1f45 = { 48 37 [2] 7a 15 [2] 7c 20 [2] 52 20 [2] 6d 3c }

  condition:
    any of them
}