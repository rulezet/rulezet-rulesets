rule TTP_XOR_WriteProcessMemory_bdf4 {
  strings:
    $key_bdf4 = { ea 86 [2] d8 a4 [2] de 91 [2] f0 91 [2] cf 8d }

  condition:
    any of them
}