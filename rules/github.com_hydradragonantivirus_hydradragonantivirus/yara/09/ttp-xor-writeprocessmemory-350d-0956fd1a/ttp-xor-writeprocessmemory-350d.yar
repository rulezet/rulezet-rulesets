rule TTP_XOR_WriteProcessMemory_350d {
  strings:
    $key_350d = { 62 7f [2] 50 5d [2] 56 68 [2] 78 68 [2] 47 74 }

  condition:
    any of them
}