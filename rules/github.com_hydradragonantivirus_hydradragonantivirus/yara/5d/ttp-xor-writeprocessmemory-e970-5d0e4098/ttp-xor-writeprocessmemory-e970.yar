rule TTP_XOR_WriteProcessMemory_e970 {
  strings:
    $key_e970 = { be 02 [2] 8c 20 [2] 8a 15 [2] a4 15 [2] 9b 09 }

  condition:
    any of them
}