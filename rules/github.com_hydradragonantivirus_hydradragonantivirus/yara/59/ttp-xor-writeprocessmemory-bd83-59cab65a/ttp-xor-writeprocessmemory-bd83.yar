rule TTP_XOR_WriteProcessMemory_bd83 {
  strings:
    $key_bd83 = { ea f1 [2] d8 d3 [2] de e6 [2] f0 e6 [2] cf fa }

  condition:
    any of them
}