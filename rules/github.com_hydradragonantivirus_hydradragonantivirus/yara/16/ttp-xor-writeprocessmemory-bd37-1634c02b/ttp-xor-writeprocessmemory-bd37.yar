rule TTP_XOR_WriteProcessMemory_bd37 {
  strings:
    $key_bd37 = { ea 45 [2] d8 67 [2] de 52 [2] f0 52 [2] cf 4e }

  condition:
    any of them
}