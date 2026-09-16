rule TTP_XOR_WriteProcessMemory_54e5 {
  strings:
    $key_54e5 = { 03 97 [2] 31 b5 [2] 37 80 [2] 19 80 [2] 26 9c }

  condition:
    any of them
}