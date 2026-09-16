rule TTP_XOR_WriteProcessMemory_1697 {
  strings:
    $key_1697 = { 41 e5 [2] 73 c7 [2] 75 f2 [2] 5b f2 [2] 64 ee }

  condition:
    any of them
}