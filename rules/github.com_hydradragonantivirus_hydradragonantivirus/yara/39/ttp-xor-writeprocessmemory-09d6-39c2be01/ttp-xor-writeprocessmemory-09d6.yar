rule TTP_XOR_WriteProcessMemory_09d6 {
  strings:
    $key_09d6 = { 5e a4 [2] 6c 86 [2] 6a b3 [2] 44 b3 [2] 7b af }

  condition:
    any of them
}