rule TTP_XOR_WriteProcessMemory_4b5d {
  strings:
    $key_4b5d = { 1c 2f [2] 2e 0d [2] 28 38 [2] 06 38 [2] 39 24 }

  condition:
    any of them
}