rule TTP_XOR_WriteProcessMemory_68e5 {
  strings:
    $key_68e5 = { 3f 97 [2] 0d b5 [2] 0b 80 [2] 25 80 [2] 1a 9c }

  condition:
    any of them
}