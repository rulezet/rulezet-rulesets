rule TTP_XOR_WriteProcessMemory_32c5 {
  strings:
    $key_32c5 = { 65 b7 [2] 57 95 [2] 51 a0 [2] 7f a0 [2] 40 bc }

  condition:
    any of them
}