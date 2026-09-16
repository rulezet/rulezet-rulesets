rule TTP_XOR_WriteProcessMemory_f997 {
  strings:
    $key_f997 = { ae e5 [2] 9c c7 [2] 9a f2 [2] b4 f2 [2] 8b ee }

  condition:
    any of them
}