rule TTP_XOR_WriteProcessMemory_825b {
  strings:
    $key_825b = { d5 29 [2] e7 0b [2] e1 3e [2] cf 3e [2] f0 22 }

  condition:
    any of them
}