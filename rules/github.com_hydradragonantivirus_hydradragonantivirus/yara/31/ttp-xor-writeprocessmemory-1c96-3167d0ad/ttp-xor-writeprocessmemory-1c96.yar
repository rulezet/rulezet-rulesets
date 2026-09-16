rule TTP_XOR_WriteProcessMemory_1c96 {
  strings:
    $key_1c96 = { 4b e4 [2] 79 c6 [2] 7f f3 [2] 51 f3 [2] 6e ef }

  condition:
    any of them
}