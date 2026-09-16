rule TTP_XOR_WriteProcessMemory_3745 {
  strings:
    $key_3745 = { 60 37 [2] 52 15 [2] 54 20 [2] 7a 20 [2] 45 3c }

  condition:
    any of them
}