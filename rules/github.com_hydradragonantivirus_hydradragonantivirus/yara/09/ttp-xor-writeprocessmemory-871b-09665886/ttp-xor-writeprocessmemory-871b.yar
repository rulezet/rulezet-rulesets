rule TTP_XOR_WriteProcessMemory_871b {
  strings:
    $key_871b = { d0 69 [2] e2 4b [2] e4 7e [2] ca 7e [2] f5 62 }

  condition:
    any of them
}