rule TTP_XOR_WriteProcessMemory_cc28 {
  strings:
    $key_cc28 = { 9b 5a [2] a9 78 [2] af 4d [2] 81 4d [2] be 51 }

  condition:
    any of them
}