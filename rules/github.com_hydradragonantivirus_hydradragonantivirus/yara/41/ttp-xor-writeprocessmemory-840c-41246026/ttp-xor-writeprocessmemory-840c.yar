rule TTP_XOR_WriteProcessMemory_840c {
  strings:
    $key_840c = { d3 7e [2] e1 5c [2] e7 69 [2] c9 69 [2] f6 75 }

  condition:
    any of them
}