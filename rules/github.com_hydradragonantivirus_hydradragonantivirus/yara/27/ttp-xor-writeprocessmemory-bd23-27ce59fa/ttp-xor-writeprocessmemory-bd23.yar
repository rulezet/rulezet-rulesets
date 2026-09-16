rule TTP_XOR_WriteProcessMemory_bd23 {
  strings:
    $key_bd23 = { ea 51 [2] d8 73 [2] de 46 [2] f0 46 [2] cf 5a }

  condition:
    any of them
}