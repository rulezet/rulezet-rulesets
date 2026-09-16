rule TTP_XOR_WriteProcessMemory_6692 {
  strings:
    $key_6692 = { 31 e0 [2] 03 c2 [2] 05 f7 [2] 2b f7 [2] 14 eb }

  condition:
    any of them
}