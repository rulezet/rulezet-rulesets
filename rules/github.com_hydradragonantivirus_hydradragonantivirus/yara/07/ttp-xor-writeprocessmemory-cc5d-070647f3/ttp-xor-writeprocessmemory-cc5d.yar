rule TTP_XOR_WriteProcessMemory_cc5d {
  strings:
    $key_cc5d = { 9b 2f [2] a9 0d [2] af 38 [2] 81 38 [2] be 24 }

  condition:
    any of them
}