rule TTP_XOR_WriteProcessMemory_8bc9 {
  strings:
    $key_8bc9 = { dc bb [2] ee 99 [2] e8 ac [2] c6 ac [2] f9 b0 }

  condition:
    any of them
}