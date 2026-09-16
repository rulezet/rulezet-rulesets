rule TTP_XOR_WriteProcessMemory_1c94 {
  strings:
    $key_1c94 = { 4b e6 [2] 79 c4 [2] 7f f1 [2] 51 f1 [2] 6e ed }

  condition:
    any of them
}