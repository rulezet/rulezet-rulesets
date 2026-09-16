rule TTP_XOR_WriteProcessMemory_8ed9 {
  strings:
    $key_8ed9 = { d9 ab [2] eb 89 [2] ed bc [2] c3 bc [2] fc a0 }

  condition:
    any of them
}