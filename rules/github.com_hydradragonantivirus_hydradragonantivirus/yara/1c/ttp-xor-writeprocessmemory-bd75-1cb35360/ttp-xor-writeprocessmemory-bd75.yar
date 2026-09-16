rule TTP_XOR_WriteProcessMemory_bd75 {
  strings:
    $key_bd75 = { ea 07 [2] d8 25 [2] de 10 [2] f0 10 [2] cf 0c }

  condition:
    any of them
}