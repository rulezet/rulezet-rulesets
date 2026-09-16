rule TTP_XOR_WriteProcessMemory_1cd9 {
  strings:
    $key_1cd9 = { 4b ab [2] 79 89 [2] 7f bc [2] 51 bc [2] 6e a0 }

  condition:
    any of them
}