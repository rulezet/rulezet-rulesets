rule TTP_XOR_WriteProcessMemory_4c96 {
  strings:
    $key_4c96 = { 1b e4 [2] 29 c6 [2] 2f f3 [2] 01 f3 [2] 3e ef }

  condition:
    any of them
}