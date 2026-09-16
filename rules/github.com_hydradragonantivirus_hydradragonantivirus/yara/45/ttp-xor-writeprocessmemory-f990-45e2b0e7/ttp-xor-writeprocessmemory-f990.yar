rule TTP_XOR_WriteProcessMemory_f990 {
  strings:
    $key_f990 = { ae e2 [2] 9c c0 [2] 9a f5 [2] b4 f5 [2] 8b e9 }

  condition:
    any of them
}