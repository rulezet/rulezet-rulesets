rule TTP_XOR_WriteProcessMemory_876e {
  strings:
    $key_876e = { d0 1c [2] e2 3e [2] e4 0b [2] ca 0b [2] f5 17 }

  condition:
    any of them
}