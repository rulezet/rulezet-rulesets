rule TTP_XOR_WriteProcessMemory_afce {
  strings:
    $key_afce = { f8 bc [2] ca 9e [2] cc ab [2] e2 ab [2] dd b7 }

  condition:
    any of them
}