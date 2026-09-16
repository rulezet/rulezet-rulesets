rule TTP_XOR_WriteProcessMemory_563b {
  strings:
    $key_563b = { 01 49 [2] 33 6b [2] 35 5e [2] 1b 5e [2] 24 42 }

  condition:
    any of them
}