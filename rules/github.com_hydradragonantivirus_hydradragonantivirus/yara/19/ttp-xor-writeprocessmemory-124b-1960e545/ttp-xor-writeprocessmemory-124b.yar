rule TTP_XOR_WriteProcessMemory_124b {
  strings:
    $key_124b = { 45 39 [2] 77 1b [2] 71 2e [2] 5f 2e [2] 60 32 }

  condition:
    any of them
}