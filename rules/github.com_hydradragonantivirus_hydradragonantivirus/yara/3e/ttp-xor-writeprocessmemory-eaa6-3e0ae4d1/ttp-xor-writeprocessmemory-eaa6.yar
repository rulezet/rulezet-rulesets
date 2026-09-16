rule TTP_XOR_WriteProcessMemory_eaa6 {
  strings:
    $key_eaa6 = { bd d4 [2] 8f f6 [2] 89 c3 [2] a7 c3 [2] 98 df }

  condition:
    any of them
}