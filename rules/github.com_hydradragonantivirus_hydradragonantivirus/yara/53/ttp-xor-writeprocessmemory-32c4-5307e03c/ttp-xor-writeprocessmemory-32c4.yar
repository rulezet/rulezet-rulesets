rule TTP_XOR_WriteProcessMemory_32c4 {
  strings:
    $key_32c4 = { 65 b6 [2] 57 94 [2] 51 a1 [2] 7f a1 [2] 40 bd }

  condition:
    any of them
}