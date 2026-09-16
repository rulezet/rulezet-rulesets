rule TTP_XOR_WriteProcessMemory_bdea {
  strings:
    $key_bdea = { ea 98 [2] d8 ba [2] de 8f [2] f0 8f [2] cf 93 }

  condition:
    any of them
}