rule TTP_XOR_WriteProcessMemory_3c96 {
  strings:
    $key_3c96 = { 6b e4 [2] 59 c6 [2] 5f f3 [2] 71 f3 [2] 4e ef }

  condition:
    any of them
}