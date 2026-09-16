rule TTP_XOR_WriteProcessMemory_535d {
  strings:
    $key_535d = { 04 2f [2] 36 0d [2] 30 38 [2] 1e 38 [2] 21 24 }

  condition:
    any of them
}