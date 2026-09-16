rule TTP_XOR_WriteProcessMemory_fdd9 {
  strings:
    $key_fdd9 = { aa ab [2] 98 89 [2] 9e bc [2] b0 bc [2] 8f a0 }

  condition:
    any of them
}