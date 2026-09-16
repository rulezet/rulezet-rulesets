rule TTP_XOR_WriteProcessMemory_ef50 {
  strings:
    $key_ef50 = { b8 22 [2] 8a 00 [2] 8c 35 [2] a2 35 [2] 9d 29 }

  condition:
    any of them
}