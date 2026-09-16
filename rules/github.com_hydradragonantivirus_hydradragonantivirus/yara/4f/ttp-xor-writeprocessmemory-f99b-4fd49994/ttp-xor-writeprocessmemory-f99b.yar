rule TTP_XOR_WriteProcessMemory_f99b {
  strings:
    $key_f99b = { ae e9 [2] 9c cb [2] 9a fe [2] b4 fe [2] 8b e2 }

  condition:
    any of them
}