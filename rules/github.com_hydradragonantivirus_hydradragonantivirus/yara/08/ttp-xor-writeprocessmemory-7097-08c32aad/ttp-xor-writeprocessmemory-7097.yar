rule TTP_XOR_WriteProcessMemory_7097 {
  strings:
    $key_7097 = { 27 e5 [2] 15 c7 [2] 13 f2 [2] 3d f2 [2] 02 ee }

  condition:
    any of them
}