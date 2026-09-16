rule TTP_XOR_WriteProcessMemory_173b {
  strings:
    $key_173b = { 40 49 [2] 72 6b [2] 74 5e [2] 5a 5e [2] 65 42 }

  condition:
    any of them
}