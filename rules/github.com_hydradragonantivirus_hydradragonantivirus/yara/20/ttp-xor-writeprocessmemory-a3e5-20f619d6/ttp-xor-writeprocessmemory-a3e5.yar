rule TTP_XOR_WriteProcessMemory_a3e5 {
  strings:
    $key_a3e5 = { f4 97 [2] c6 b5 [2] c0 80 [2] ee 80 [2] d1 9c }

  condition:
    any of them
}