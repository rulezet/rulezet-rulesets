rule TTP_XOR_WriteProcessMemory_31e5 {
  strings:
    $key_31e5 = { 66 97 [2] 54 b5 [2] 52 80 [2] 7c 80 [2] 43 9c }

  condition:
    any of them
}