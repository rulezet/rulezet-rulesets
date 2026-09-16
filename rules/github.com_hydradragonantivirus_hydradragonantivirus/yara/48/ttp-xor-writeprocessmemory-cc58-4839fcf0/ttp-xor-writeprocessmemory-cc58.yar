rule TTP_XOR_WriteProcessMemory_cc58 {
  strings:
    $key_cc58 = { 9b 2a [2] a9 08 [2] af 3d [2] 81 3d [2] be 21 }

  condition:
    any of them
}