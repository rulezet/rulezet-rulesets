rule TTP_XOR_WriteProcessMemory_025d {
  strings:
    $key_025d = { 55 2f [2] 67 0d [2] 61 38 [2] 4f 38 [2] 70 24 }

  condition:
    any of them
}