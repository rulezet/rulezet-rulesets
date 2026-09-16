rule TTP_XOR_WriteProcessMemory_eaa0 {
  strings:
    $key_eaa0 = { bd d2 [2] 8f f0 [2] 89 c5 [2] a7 c5 [2] 98 d9 }

  condition:
    any of them
}