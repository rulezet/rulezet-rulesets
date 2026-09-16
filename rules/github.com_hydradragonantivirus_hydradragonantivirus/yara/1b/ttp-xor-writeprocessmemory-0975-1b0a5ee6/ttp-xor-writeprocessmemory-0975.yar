rule TTP_XOR_WriteProcessMemory_0975 {
  strings:
    $key_0975 = { 5e 07 [2] 6c 25 [2] 6a 10 [2] 44 10 [2] 7b 0c }

  condition:
    any of them
}