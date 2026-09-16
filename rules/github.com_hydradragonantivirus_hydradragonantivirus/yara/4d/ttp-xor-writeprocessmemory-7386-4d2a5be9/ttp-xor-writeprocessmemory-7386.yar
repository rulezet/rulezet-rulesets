rule TTP_XOR_WriteProcessMemory_7386 {
  strings:
    $key_7386 = { 24 f4 [2] 16 d6 [2] 10 e3 [2] 3e e3 [2] 01 ff }

  condition:
    any of them
}