rule TTP_XOR_WriteProcessMemory_f99c {
  strings:
    $key_f99c = { ae ee [2] 9c cc [2] 9a f9 [2] b4 f9 [2] 8b e5 }

  condition:
    any of them
}