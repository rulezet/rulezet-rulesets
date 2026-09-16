rule TTP_XOR_WriteProcessMemory_0884 {
  strings:
    $key_0884 = { 5f f6 [2] 6d d4 [2] 6b e1 [2] 45 e1 [2] 7a fd }

  condition:
    any of them
}