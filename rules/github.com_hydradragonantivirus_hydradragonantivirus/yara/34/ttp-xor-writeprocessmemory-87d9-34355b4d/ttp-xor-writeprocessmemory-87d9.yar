rule TTP_XOR_WriteProcessMemory_87d9 {
  strings:
    $key_87d9 = { d0 ab [2] e2 89 [2] e4 bc [2] ca bc [2] f5 a0 }

  condition:
    any of them
}