rule TTP_XOR_WriteProcessMemory_eac3 {
  strings:
    $key_eac3 = { bd b1 [2] 8f 93 [2] 89 a6 [2] a7 a6 [2] 98 ba }

  condition:
    any of them
}