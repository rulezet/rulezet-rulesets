rule TTP_XOR_WriteProcessMemory_eaa3 {
  strings:
    $key_eaa3 = { bd d1 [2] 8f f3 [2] 89 c6 [2] a7 c6 [2] 98 da }

  condition:
    any of them
}