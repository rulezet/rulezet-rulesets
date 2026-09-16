rule TTP_XOR_WriteProcessMemory_bde4 {
  strings:
    $key_bde4 = { ea 96 [2] d8 b4 [2] de 81 [2] f0 81 [2] cf 9d }

  condition:
    any of them
}