rule TTP_XOR_WriteProcessMemory_bbd3 {
  strings:
    $key_bbd3 = { ec a1 [2] de 83 [2] d8 b6 [2] f6 b6 [2] c9 aa }

  condition:
    any of them
}