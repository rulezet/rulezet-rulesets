rule TTP_XOR_WriteProcessMemory_a3ee {
  strings:
    $key_a3ee = { f4 9c [2] c6 be [2] c0 8b [2] ee 8b [2] d1 97 }

  condition:
    any of them
}