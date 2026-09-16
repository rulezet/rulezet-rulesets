rule TTP_XOR_WriteProcessMemory_eee5 {
  strings:
    $key_eee5 = { b9 97 [2] 8b b5 [2] 8d 80 [2] a3 80 [2] 9c 9c }

  condition:
    any of them
}