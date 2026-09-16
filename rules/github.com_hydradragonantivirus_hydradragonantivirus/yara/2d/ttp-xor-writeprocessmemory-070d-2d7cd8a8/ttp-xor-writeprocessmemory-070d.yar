rule TTP_XOR_WriteProcessMemory_070d {
  strings:
    $key_070d = { 50 7f [2] 62 5d [2] 64 68 [2] 4a 68 [2] 75 74 }

  condition:
    any of them
}