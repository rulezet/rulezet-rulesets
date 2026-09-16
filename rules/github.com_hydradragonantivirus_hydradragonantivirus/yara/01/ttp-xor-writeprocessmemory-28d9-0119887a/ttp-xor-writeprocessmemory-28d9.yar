rule TTP_XOR_WriteProcessMemory_28d9 {
  strings:
    $key_28d9 = { 7f ab [2] 4d 89 [2] 4b bc [2] 65 bc [2] 5a a0 }

  condition:
    any of them
}