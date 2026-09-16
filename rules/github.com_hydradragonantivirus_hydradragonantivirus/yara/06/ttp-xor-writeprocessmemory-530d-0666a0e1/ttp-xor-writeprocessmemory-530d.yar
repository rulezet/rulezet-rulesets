rule TTP_XOR_WriteProcessMemory_530d {
  strings:
    $key_530d = { 04 7f [2] 36 5d [2] 30 68 [2] 1e 68 [2] 21 74 }

  condition:
    any of them
}