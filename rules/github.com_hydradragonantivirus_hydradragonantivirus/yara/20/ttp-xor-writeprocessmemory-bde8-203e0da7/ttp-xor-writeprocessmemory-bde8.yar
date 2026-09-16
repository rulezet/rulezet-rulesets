rule TTP_XOR_WriteProcessMemory_bde8 {
  strings:
    $key_bde8 = { ea 9a [2] d8 b8 [2] de 8d [2] f0 8d [2] cf 91 }

  condition:
    any of them
}