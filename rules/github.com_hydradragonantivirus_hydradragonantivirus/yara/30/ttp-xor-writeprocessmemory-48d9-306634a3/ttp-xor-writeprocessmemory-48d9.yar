rule TTP_XOR_WriteProcessMemory_48d9 {
  strings:
    $key_48d9 = { 1f ab [2] 2d 89 [2] 2b bc [2] 05 bc [2] 3a a0 }

  condition:
    any of them
}