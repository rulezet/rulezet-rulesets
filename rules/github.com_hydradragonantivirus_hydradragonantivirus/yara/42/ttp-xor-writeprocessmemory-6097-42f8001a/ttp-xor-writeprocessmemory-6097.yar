rule TTP_XOR_WriteProcessMemory_6097 {
  strings:
    $key_6097 = { 37 e5 [2] 05 c7 [2] 03 f2 [2] 2d f2 [2] 12 ee }

  condition:
    any of them
}