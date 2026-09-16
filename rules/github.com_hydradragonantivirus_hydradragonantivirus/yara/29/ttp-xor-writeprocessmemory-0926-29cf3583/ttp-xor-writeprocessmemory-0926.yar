rule TTP_XOR_WriteProcessMemory_0926 {
  strings:
    $key_0926 = { 5e 54 [2] 6c 76 [2] 6a 43 [2] 44 43 [2] 7b 5f }

  condition:
    any of them
}