rule TTP_XOR_WriteProcessMemory_cc1a {
  strings:
    $key_cc1a = { 9b 68 [2] a9 4a [2] af 7f [2] 81 7f [2] be 63 }

  condition:
    any of them
}