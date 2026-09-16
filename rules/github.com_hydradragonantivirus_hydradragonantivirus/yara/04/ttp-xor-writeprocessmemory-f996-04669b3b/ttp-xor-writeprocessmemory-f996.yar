rule TTP_XOR_WriteProcessMemory_f996 {
  strings:
    $key_f996 = { ae e4 [2] 9c c6 [2] 9a f3 [2] b4 f3 [2] 8b ef }

  condition:
    any of them
}