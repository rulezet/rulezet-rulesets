rule TTP_XOR_WriteProcessMemory_bd67 {
  strings:
    $key_bd67 = { ea 15 [2] d8 37 [2] de 02 [2] f0 02 [2] cf 1e }

  condition:
    any of them
}