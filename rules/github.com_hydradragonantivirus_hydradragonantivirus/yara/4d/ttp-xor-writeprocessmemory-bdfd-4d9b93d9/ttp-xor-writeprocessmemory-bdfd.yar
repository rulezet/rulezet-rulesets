rule TTP_XOR_WriteProcessMemory_bdfd {
  strings:
    $key_bdfd = { ea 8f [2] d8 ad [2] de 98 [2] f0 98 [2] cf 84 }

  condition:
    any of them
}