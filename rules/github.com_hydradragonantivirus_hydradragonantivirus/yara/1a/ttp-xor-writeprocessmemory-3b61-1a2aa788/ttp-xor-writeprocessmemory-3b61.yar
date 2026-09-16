rule TTP_XOR_WriteProcessMemory_3b61 {
  strings:
    $key_3b61 = { 6c 13 [2] 5e 31 [2] 58 04 [2] 76 04 [2] 49 18 }

  condition:
    any of them
}