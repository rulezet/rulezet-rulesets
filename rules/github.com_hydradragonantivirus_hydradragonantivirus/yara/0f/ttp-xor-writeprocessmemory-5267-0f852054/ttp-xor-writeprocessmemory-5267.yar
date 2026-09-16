rule TTP_XOR_WriteProcessMemory_5267 {
  strings:
    $key_5267 = { 05 15 [2] 37 37 [2] 31 02 [2] 1f 02 [2] 20 1e }

  condition:
    any of them
}