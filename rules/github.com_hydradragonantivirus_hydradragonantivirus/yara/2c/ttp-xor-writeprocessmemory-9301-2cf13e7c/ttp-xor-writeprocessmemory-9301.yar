rule TTP_XOR_WriteProcessMemory_9301 {
  strings:
    $key_9301 = { c4 73 [2] f6 51 [2] f0 64 [2] de 64 [2] e1 78 }

  condition:
    any of them
}