rule TTP_XOR_WriteProcessMemory_876c {
  strings:
    $key_876c = { d0 1e [2] e2 3c [2] e4 09 [2] ca 09 [2] f5 15 }

  condition:
    any of them
}