rule TTP_XOR_WriteProcessMemory_8bd8 {
  strings:
    $key_8bd8 = { dc aa [2] ee 88 [2] e8 bd [2] c6 bd [2] f9 a1 }

  condition:
    any of them
}