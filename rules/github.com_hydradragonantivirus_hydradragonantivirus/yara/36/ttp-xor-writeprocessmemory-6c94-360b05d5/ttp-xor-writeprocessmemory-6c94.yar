rule TTP_XOR_WriteProcessMemory_6c94 {
  strings:
    $key_6c94 = { 3b e6 [2] 09 c4 [2] 0f f1 [2] 21 f1 [2] 1e ed }

  condition:
    any of them
}