rule TTP_XOR_WriteProcessMemory_794d {
  strings:
    $key_794d = { 2e 3f [2] 1c 1d [2] 1a 28 [2] 34 28 [2] 0b 34 }

  condition:
    any of them
}