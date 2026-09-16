rule TTP_XOR_WriteProcessMemory_720d {
  strings:
    $key_720d = { 25 7f [2] 17 5d [2] 11 68 [2] 3f 68 [2] 00 74 }

  condition:
    any of them
}