rule TTP_XOR_WriteProcessMemory_66e5 {
  strings:
    $key_66e5 = { 31 97 [2] 03 b5 [2] 05 80 [2] 2b 80 [2] 14 9c }

  condition:
    any of them
}