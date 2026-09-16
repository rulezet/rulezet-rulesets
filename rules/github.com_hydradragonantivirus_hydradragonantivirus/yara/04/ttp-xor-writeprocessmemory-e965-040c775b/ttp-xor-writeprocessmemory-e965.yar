rule TTP_XOR_WriteProcessMemory_e965 {
  strings:
    $key_e965 = { be 17 [2] 8c 35 [2] 8a 00 [2] a4 00 [2] 9b 1c }

  condition:
    any of them
}