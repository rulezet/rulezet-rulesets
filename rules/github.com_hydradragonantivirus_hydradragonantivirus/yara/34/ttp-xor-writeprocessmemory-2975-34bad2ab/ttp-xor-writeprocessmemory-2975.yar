rule TTP_XOR_WriteProcessMemory_2975 {
  strings:
    $key_2975 = { 7e 07 [2] 4c 25 [2] 4a 10 [2] 64 10 [2] 5b 0c }

  condition:
    any of them
}