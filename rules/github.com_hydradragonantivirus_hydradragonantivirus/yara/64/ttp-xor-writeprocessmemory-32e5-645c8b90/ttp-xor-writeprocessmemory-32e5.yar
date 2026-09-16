rule TTP_XOR_WriteProcessMemory_32e5 {
  strings:
    $key_32e5 = { 65 97 [2] 57 b5 [2] 51 80 [2] 7f 80 [2] 40 9c }

  condition:
    any of them
}