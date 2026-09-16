rule TTP_XOR_WriteProcessMemory_826b {
  strings:
    $key_826b = { d5 19 [2] e7 3b [2] e1 0e [2] cf 0e [2] f0 12 }

  condition:
    any of them
}