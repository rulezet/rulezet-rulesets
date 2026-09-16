rule TTP_XOR_WriteProcessMemory_7786 {
  strings:
    $key_7786 = { 20 f4 [2] 12 d6 [2] 14 e3 [2] 3a e3 [2] 05 ff }

  condition:
    any of them
}