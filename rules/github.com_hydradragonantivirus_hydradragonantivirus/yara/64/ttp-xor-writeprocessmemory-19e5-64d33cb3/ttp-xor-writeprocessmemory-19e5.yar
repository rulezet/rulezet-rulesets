rule TTP_XOR_WriteProcessMemory_19e5 {
  strings:
    $key_19e5 = { 4e 97 [2] 7c b5 [2] 7a 80 [2] 54 80 [2] 6b 9c }

  condition:
    any of them
}