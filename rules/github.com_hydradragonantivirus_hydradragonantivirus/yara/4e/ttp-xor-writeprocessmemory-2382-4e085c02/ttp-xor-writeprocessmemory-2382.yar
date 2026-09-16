rule TTP_XOR_WriteProcessMemory_2382 {
  strings:
    $key_2382 = { 74 f0 [2] 46 d2 [2] 40 e7 [2] 6e e7 [2] 51 fb }

  condition:
    any of them
}