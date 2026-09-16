rule TTP_XOR_WriteProcessMemory_532b {
  strings:
    $key_532b = { 04 59 [2] 36 7b [2] 30 4e [2] 1e 4e [2] 21 52 }

  condition:
    any of them
}