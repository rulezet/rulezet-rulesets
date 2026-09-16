rule TTP_XOR_WriteProcessMemory_bd19 {
  strings:
    $key_bd19 = { ea 6b [2] d8 49 [2] de 7c [2] f0 7c [2] cf 60 }

  condition:
    any of them
}