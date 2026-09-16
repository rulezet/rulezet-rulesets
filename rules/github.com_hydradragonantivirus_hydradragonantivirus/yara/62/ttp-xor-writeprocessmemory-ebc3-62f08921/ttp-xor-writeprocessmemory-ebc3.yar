rule TTP_XOR_WriteProcessMemory_ebc3 {
  strings:
    $key_ebc3 = { bc b1 [2] 8e 93 [2] 88 a6 [2] a6 a6 [2] 99 ba }

  condition:
    any of them
}