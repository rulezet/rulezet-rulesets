rule TTP_XOR_WriteProcessMemory_6de5 {
  strings:
    $key_6de5 = { 3a 97 [2] 08 b5 [2] 0e 80 [2] 20 80 [2] 1f 9c }

  condition:
    any of them
}