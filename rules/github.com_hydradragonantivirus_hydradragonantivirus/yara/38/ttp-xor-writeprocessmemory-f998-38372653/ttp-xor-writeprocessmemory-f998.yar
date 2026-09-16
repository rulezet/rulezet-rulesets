rule TTP_XOR_WriteProcessMemory_f998 {
  strings:
    $key_f998 = { ae ea [2] 9c c8 [2] 9a fd [2] b4 fd [2] 8b e1 }

  condition:
    any of them
}