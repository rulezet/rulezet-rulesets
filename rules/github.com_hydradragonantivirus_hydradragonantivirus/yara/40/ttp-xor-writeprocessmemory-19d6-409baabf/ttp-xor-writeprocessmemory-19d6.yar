rule TTP_XOR_WriteProcessMemory_19d6 {
  strings:
    $key_19d6 = { 4e a4 [2] 7c 86 [2] 7a b3 [2] 54 b3 [2] 6b af }

  condition:
    any of them
}