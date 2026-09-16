rule TTP_XOR_WriteProcessMemory_cc38 {
  strings:
    $key_cc38 = { 9b 4a [2] a9 68 [2] af 5d [2] 81 5d [2] be 41 }

  condition:
    any of them
}