rule TTP_XOR_WriteProcessMemory_5b61 {
  strings:
    $key_5b61 = { 0c 13 [2] 3e 31 [2] 38 04 [2] 16 04 [2] 29 18 }

  condition:
    any of them
}