rule TTP_XOR_WriteProcessMemory_6cd9 {
  strings:
    $key_6cd9 = { 3b ab [2] 09 89 [2] 0f bc [2] 21 bc [2] 1e a0 }

  condition:
    any of them
}