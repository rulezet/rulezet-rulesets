rule TTP_XOR_WriteProcessMemory_512d {
  strings:
    $key_512d = { 06 5f [2] 34 7d [2] 32 48 [2] 1c 48 [2] 23 54 }

  condition:
    any of them
}