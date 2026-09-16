rule TTP_XOR_WriteProcessMemory_bd47 {
  strings:
    $key_bd47 = { ea 35 [2] d8 17 [2] de 22 [2] f0 22 [2] cf 3e }

  condition:
    any of them
}