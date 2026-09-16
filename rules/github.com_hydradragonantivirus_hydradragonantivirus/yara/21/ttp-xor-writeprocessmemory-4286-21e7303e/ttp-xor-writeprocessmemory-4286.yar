rule TTP_XOR_WriteProcessMemory_4286 {
  strings:
    $key_4286 = { 15 f4 [2] 27 d6 [2] 21 e3 [2] 0f e3 [2] 30 ff }

  condition:
    any of them
}