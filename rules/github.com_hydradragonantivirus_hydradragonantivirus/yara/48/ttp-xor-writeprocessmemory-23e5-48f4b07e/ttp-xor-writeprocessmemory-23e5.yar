rule TTP_XOR_WriteProcessMemory_23e5 {
  strings:
    $key_23e5 = { 74 97 [2] 46 b5 [2] 40 80 [2] 6e 80 [2] 51 9c }

  condition:
    any of them
}