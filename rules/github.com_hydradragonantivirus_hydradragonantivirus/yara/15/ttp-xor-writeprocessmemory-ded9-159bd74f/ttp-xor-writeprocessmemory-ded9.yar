rule TTP_XOR_WriteProcessMemory_ded9 {
  strings:
    $key_ded9 = { 89 ab [2] bb 89 [2] bd bc [2] 93 bc [2] ac a0 }

  condition:
    any of them
}