rule TTP_XOR_WriteProcessMemory_6b61 {
  strings:
    $key_6b61 = { 3c 13 [2] 0e 31 [2] 08 04 [2] 26 04 [2] 19 18 }

  condition:
    any of them
}