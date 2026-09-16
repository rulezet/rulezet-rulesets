rule TTP_XOR_WriteProcessMemory_bda5 {
  strings:
    $key_bda5 = { ea d7 [2] d8 f5 [2] de c0 [2] f0 c0 [2] cf dc }

  condition:
    any of them
}