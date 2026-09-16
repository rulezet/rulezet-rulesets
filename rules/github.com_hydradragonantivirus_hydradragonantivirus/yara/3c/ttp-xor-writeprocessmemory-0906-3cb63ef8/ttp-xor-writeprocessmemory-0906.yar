rule TTP_XOR_WriteProcessMemory_0906 {
  strings:
    $key_0906 = { 5e 74 [2] 6c 56 [2] 6a 63 [2] 44 63 [2] 7b 7f }

  condition:
    any of them
}