rule TTP_XOR_WriteProcessMemory_bdb8 {
  strings:
    $key_bdb8 = { ea ca [2] d8 e8 [2] de dd [2] f0 dd [2] cf c1 }

  condition:
    any of them
}