rule TTP_XOR_WriteProcessMemory_aca5 {
  strings:
    $key_aca5 = { fb d7 [2] c9 f5 [2] cf c0 [2] e1 c0 [2] de dc }

  condition:
    any of them
}