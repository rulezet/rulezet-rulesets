rule TTP_XOR_WriteProcessMemory_440d {
  strings:
    $key_440d = { 13 7f [2] 21 5d [2] 27 68 [2] 09 68 [2] 36 74 }

  condition:
    any of them
}