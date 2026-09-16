rule TTP_XOR_WriteProcessMemory_39d9 {
  strings:
    $key_39d9 = { 6e ab [2] 5c 89 [2] 5a bc [2] 74 bc [2] 4b a0 }

  condition:
    any of them
}