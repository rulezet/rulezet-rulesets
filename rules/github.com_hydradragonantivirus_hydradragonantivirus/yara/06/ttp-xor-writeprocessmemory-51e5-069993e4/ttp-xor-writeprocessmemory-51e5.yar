rule TTP_XOR_WriteProcessMemory_51e5 {
  strings:
    $key_51e5 = { 06 97 [2] 34 b5 [2] 32 80 [2] 1c 80 [2] 23 9c }

  condition:
    any of them
}