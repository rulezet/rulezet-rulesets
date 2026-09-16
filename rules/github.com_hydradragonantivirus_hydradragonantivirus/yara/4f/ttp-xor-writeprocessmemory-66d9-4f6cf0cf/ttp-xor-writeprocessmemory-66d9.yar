rule TTP_XOR_WriteProcessMemory_66d9 {
  strings:
    $key_66d9 = { 31 ab [2] 03 89 [2] 05 bc [2] 2b bc [2] 14 a0 }

  condition:
    any of them
}