rule TTP_XOR_WriteProcessMemory_230d {
  strings:
    $key_230d = { 74 7f [2] 46 5d [2] 40 68 [2] 6e 68 [2] 51 74 }

  condition:
    any of them
}