rule TTP_XOR_WriteProcessMemory_69d9 {
  strings:
    $key_69d9 = { 3e ab [2] 0c 89 [2] 0a bc [2] 24 bc [2] 1b a0 }

  condition:
    any of them
}