rule TTP_XOR_WriteProcessMemory_877b {
  strings:
    $key_877b = { d0 09 [2] e2 2b [2] e4 1e [2] ca 1e [2] f5 02 }

  condition:
    any of them
}