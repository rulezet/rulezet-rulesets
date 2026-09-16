rule TTP_XOR_WriteProcessMemory_6ee5 {
  strings:
    $key_6ee5 = { 39 97 [2] 0b b5 [2] 0d 80 [2] 23 80 [2] 1c 9c }

  condition:
    any of them
}