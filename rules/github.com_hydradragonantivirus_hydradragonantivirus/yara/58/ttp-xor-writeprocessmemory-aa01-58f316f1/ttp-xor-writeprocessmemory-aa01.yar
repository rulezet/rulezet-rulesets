rule TTP_XOR_WriteProcessMemory_aa01 {
  strings:
    $key_aa01 = { fd 73 [2] cf 51 [2] c9 64 [2] e7 64 [2] d8 78 }

  condition:
    any of them
}