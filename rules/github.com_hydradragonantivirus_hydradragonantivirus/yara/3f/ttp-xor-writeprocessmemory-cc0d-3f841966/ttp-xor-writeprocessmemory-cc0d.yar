rule TTP_XOR_WriteProcessMemory_cc0d {
  strings:
    $key_cc0d = { 9b 7f [2] a9 5d [2] af 68 [2] 81 68 [2] be 74 }

  condition:
    any of them
}