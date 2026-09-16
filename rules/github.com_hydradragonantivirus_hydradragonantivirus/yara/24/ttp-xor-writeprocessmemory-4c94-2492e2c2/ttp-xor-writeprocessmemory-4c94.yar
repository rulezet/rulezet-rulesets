rule TTP_XOR_WriteProcessMemory_4c94 {
  strings:
    $key_4c94 = { 1b e6 [2] 29 c4 [2] 2f f1 [2] 01 f1 [2] 3e ed }

  condition:
    any of them
}