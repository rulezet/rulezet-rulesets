rule TTP_XOR_WriteProcessMemory_660d {
  strings:
    $key_660d = { 31 7f [2] 03 5d [2] 05 68 [2] 2b 68 [2] 14 74 }

  condition:
    any of them
}