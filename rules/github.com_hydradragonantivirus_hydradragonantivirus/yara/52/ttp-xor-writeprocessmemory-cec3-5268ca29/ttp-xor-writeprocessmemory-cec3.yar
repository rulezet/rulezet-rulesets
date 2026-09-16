rule TTP_XOR_WriteProcessMemory_cec3 {
  strings:
    $key_cec3 = { 99 b1 [2] ab 93 [2] ad a6 [2] 83 a6 [2] bc ba }

  condition:
    any of them
}