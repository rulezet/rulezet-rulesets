rule TTP_XOR_WriteProcessMemory_09d1 {
  strings:
    $key_09d1 = { 5e a3 [2] 6c 81 [2] 6a b4 [2] 44 b4 [2] 7b a8 }

  condition:
    any of them
}