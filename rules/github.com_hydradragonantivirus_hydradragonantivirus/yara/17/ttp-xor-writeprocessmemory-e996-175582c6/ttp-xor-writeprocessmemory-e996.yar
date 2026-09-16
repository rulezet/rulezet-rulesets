rule TTP_XOR_WriteProcessMemory_e996 {
  strings:
    $key_e996 = { be e4 [2] 8c c6 [2] 8a f3 [2] a4 f3 [2] 9b ef }

  condition:
    any of them
}