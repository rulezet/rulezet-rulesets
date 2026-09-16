rule TTP_XOR_WriteProcessMemory_630d {
  strings:
    $key_630d = { 34 7f [2] 06 5d [2] 00 68 [2] 2e 68 [2] 11 74 }

  condition:
    any of them
}