rule TTP_XOR_WriteProcessMemory_bd05 {
  strings:
    $key_bd05 = { ea 77 [2] d8 55 [2] de 60 [2] f0 60 [2] cf 7c }

  condition:
    any of them
}