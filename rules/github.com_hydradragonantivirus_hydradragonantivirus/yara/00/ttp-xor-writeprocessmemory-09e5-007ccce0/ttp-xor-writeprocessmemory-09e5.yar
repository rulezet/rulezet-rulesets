rule TTP_XOR_WriteProcessMemory_09e5 {
  strings:
    $key_09e5 = { 5e 97 [2] 6c b5 [2] 6a 80 [2] 44 80 [2] 7b 9c }

  condition:
    any of them
}