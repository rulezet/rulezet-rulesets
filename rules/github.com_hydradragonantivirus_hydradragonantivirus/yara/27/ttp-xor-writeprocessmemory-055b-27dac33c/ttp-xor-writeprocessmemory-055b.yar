rule TTP_XOR_WriteProcessMemory_055b {
  strings:
    $key_055b = { 52 29 [2] 60 0b [2] 66 3e [2] 48 3e [2] 77 22 }

  condition:
    any of them
}