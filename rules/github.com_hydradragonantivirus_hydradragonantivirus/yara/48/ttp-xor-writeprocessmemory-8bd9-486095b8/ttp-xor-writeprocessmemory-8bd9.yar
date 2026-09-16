rule TTP_XOR_WriteProcessMemory_8bd9 {
  strings:
    $key_8bd9 = { dc ab [2] ee 89 [2] e8 bc [2] c6 bc [2] f9 a0 }

  condition:
    any of them
}