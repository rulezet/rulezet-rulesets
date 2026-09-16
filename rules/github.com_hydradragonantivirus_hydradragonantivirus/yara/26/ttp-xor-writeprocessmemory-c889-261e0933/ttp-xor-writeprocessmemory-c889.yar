rule TTP_XOR_WriteProcessMemory_c889 {
  strings:
    $key_c889 = { 9f fb [2] ad d9 [2] ab ec [2] 85 ec [2] ba f0 }

  condition:
    any of them
}