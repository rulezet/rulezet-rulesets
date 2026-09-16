rule TTP_XOR_WriteProcessMemory_4b2d {
  strings:
    $key_4b2d = { 1c 5f [2] 2e 7d [2] 28 48 [2] 06 48 [2] 39 54 }

  condition:
    any of them
}