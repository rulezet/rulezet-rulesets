rule TTP_XOR_WriteProcessMemory_34e5 {
  strings:
    $key_34e5 = { 63 97 [2] 51 b5 [2] 57 80 [2] 79 80 [2] 46 9c }

  condition:
    any of them
}