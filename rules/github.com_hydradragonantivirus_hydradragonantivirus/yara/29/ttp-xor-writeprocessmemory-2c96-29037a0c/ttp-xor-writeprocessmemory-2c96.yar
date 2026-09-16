rule TTP_XOR_WriteProcessMemory_2c96 {
  strings:
    $key_2c96 = { 7b e4 [2] 49 c6 [2] 4f f3 [2] 61 f3 [2] 5e ef }

  condition:
    any of them
}