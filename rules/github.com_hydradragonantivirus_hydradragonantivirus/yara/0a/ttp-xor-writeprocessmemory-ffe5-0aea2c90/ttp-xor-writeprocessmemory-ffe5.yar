rule TTP_XOR_WriteProcessMemory_ffe5 {
  strings:
    $key_ffe5 = { a8 97 [2] 9a b5 [2] 9c 80 [2] b2 80 [2] 8d 9c }

  condition:
    any of them
}