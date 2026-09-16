rule TTP_XOR_WriteProcessMemory_40e5 {
  strings:
    $key_40e5 = { 17 97 [2] 25 b5 [2] 23 80 [2] 0d 80 [2] 32 9c }

  condition:
    any of them
}