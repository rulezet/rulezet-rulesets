rule TTP_XOR_WriteProcessMemory_0386 {
  strings:
    $key_0386 = { 54 f4 [2] 66 d6 [2] 60 e3 [2] 4e e3 [2] 71 ff }

  condition:
    any of them
}