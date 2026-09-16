rule TTP_XOR_WriteProcessMemory_113d {
  strings:
    $key_113d = { 46 4f [2] 74 6d [2] 72 58 [2] 5c 58 [2] 63 44 }

  condition:
    any of them
}