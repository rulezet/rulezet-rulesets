rule TTP_XOR_WriteProcessMemory_5692 {
  strings:
    $key_5692 = { 01 e0 [2] 33 c2 [2] 35 f7 [2] 1b f7 [2] 24 eb }

  condition:
    any of them
}