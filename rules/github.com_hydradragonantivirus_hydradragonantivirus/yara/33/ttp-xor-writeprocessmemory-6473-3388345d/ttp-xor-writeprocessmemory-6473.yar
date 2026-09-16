rule TTP_XOR_WriteProcessMemory_6473 {
  strings:
    $key_6473 = { 33 01 [2] 01 23 [2] 07 16 [2] 29 16 [2] 16 0a }

  condition:
    any of them
}