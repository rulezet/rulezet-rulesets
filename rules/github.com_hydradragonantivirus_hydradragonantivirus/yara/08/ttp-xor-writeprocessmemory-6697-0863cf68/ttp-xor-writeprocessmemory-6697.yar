rule TTP_XOR_WriteProcessMemory_6697 {
  strings:
    $key_6697 = { 31 e5 [2] 03 c7 [2] 05 f2 [2] 2b f2 [2] 14 ee }

  condition:
    any of them
}