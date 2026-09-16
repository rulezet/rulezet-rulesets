rule TTP_XOR_WriteProcessMemory_69a9 {
  strings:
    $key_69a9 = { 3e db [2] 0c f9 [2] 0a cc [2] 24 cc [2] 1b d0 }

  condition:
    any of them
}