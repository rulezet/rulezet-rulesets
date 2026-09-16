rule TTP_XOR_WriteProcessMemory_834b {
  strings:
    $key_834b = { d4 39 [2] e6 1b [2] e0 2e [2] ce 2e [2] f1 32 }

  condition:
    any of them
}