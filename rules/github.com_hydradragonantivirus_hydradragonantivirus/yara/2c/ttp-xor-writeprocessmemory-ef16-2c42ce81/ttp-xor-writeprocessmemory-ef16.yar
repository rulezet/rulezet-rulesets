rule TTP_XOR_WriteProcessMemory_ef16 {
  strings:
    $key_ef16 = { b8 64 [2] 8a 46 [2] 8c 73 [2] a2 73 [2] 9d 6f }

  condition:
    any of them
}