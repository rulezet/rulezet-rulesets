rule TTP_XOR_WriteProcessMemory_6691 {
  strings:
    $key_6691 = { 31 e3 [2] 03 c1 [2] 05 f4 [2] 2b f4 [2] 14 e8 }

  condition:
    any of them
}