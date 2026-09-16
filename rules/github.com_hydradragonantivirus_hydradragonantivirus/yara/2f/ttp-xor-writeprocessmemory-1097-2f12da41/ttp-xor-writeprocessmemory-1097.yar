rule TTP_XOR_WriteProcessMemory_1097 {
  strings:
    $key_1097 = { 47 e5 [2] 75 c7 [2] 73 f2 [2] 5d f2 [2] 62 ee }

  condition:
    any of them
}