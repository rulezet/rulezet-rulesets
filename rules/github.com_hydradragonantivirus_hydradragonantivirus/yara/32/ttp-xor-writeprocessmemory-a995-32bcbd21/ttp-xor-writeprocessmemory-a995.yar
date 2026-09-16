rule TTP_XOR_WriteProcessMemory_a995 {
  strings:
    $key_a995 = { fe e7 [2] cc c5 [2] ca f0 [2] e4 f0 [2] db ec }

  condition:
    any of them
}