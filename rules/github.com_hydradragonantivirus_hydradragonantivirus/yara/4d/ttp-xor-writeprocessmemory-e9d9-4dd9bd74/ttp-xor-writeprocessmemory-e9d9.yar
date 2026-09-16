rule TTP_XOR_WriteProcessMemory_e9d9 {
  strings:
    $key_e9d9 = { be ab [2] 8c 89 [2] 8a bc [2] a4 bc [2] 9b a0 }

  condition:
    any of them
}