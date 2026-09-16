rule TTP_XOR_WriteProcessMemory_a317 {
  strings:
    $key_a317 = { f4 65 [2] c6 47 [2] c0 72 [2] ee 72 [2] d1 6e }

  condition:
    any of them
}