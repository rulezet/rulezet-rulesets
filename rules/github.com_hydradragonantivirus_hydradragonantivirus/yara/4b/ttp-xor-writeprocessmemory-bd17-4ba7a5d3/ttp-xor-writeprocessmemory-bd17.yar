rule TTP_XOR_WriteProcessMemory_bd17 {
  strings:
    $key_bd17 = { ea 65 [2] d8 47 [2] de 72 [2] f0 72 [2] cf 6e }

  condition:
    any of them
}