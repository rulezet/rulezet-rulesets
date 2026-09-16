rule TTP_XOR_WriteProcessMemory_b8d9 {
  strings:
    $key_b8d9 = { ef ab [2] dd 89 [2] db bc [2] f5 bc [2] ca a0 }

  condition:
    any of them
}