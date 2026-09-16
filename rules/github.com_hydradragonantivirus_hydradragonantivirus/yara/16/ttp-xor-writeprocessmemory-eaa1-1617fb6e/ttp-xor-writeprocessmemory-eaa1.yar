rule TTP_XOR_WriteProcessMemory_eaa1 {
  strings:
    $key_eaa1 = { bd d3 [2] 8f f1 [2] 89 c4 [2] a7 c4 [2] 98 d8 }

  condition:
    any of them
}