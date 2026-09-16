rule TTP_XOR_WriteProcessMemory_725d {
  strings:
    $key_725d = { 25 2f [2] 17 0d [2] 11 38 [2] 3f 38 [2] 00 24 }

  condition:
    any of them
}