rule TTP_XOR_WriteProcessMemory_a3fc {
  strings:
    $key_a3fc = { f4 8e [2] c6 ac [2] c0 99 [2] ee 99 [2] d1 85 }

  condition:
    any of them
}