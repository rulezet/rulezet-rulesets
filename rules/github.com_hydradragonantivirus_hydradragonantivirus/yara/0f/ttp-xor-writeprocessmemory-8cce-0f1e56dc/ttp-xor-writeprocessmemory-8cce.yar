rule TTP_XOR_WriteProcessMemory_8cce {
  strings:
    $key_8cce = { db bc [2] e9 9e [2] ef ab [2] c1 ab [2] fe b7 }

  condition:
    any of them
}