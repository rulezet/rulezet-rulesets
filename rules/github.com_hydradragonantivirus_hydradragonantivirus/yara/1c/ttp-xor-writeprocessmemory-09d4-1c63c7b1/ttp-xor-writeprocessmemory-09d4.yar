rule TTP_XOR_WriteProcessMemory_09d4 {
  strings:
    $key_09d4 = { 5e a6 [2] 6c 84 [2] 6a b1 [2] 44 b1 [2] 7b ad }

  condition:
    any of them
}