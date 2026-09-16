rule TTP_XOR_WriteProcessMemory_bbc8 {
  strings:
    $key_bbc8 = { ec ba [2] de 98 [2] d8 ad [2] f6 ad [2] c9 b1 }

  condition:
    any of them
}