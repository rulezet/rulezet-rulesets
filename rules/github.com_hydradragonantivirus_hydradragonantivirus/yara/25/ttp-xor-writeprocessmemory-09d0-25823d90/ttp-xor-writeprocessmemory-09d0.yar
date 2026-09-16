rule TTP_XOR_WriteProcessMemory_09d0 {
  strings:
    $key_09d0 = { 5e a2 [2] 6c 80 [2] 6a b5 [2] 44 b5 [2] 7b a9 }

  condition:
    any of them
}