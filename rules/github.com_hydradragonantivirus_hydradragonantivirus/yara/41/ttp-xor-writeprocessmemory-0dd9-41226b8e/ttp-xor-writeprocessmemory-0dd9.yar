rule TTP_XOR_WriteProcessMemory_0dd9 {
  strings:
    $key_0dd9 = { 5a ab [2] 68 89 [2] 6e bc [2] 40 bc [2] 7f a0 }

  condition:
    any of them
}