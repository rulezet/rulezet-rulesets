rule TTP_XOR_WriteProcessMemory_cdd9 {
  strings:
    $key_cdd9 = { 9a ab [2] a8 89 [2] ae bc [2] 80 bc [2] bf a0 }

  condition:
    any of them
}