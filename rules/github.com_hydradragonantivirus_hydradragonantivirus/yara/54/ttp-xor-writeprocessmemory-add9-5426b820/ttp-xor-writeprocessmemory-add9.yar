rule TTP_XOR_WriteProcessMemory_add9 {
  strings:
    $key_add9 = { fa ab [2] c8 89 [2] ce bc [2] e0 bc [2] df a0 }

  condition:
    any of them
}