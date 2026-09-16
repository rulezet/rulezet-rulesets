rule TTP_XOR_WriteProcessMemory_490d {
  strings:
    $key_490d = { 1e 7f [2] 2c 5d [2] 2a 68 [2] 04 68 [2] 3b 74 }

  condition:
    any of them
}