rule TTP_XOR_WriteProcessMemory_4b0d {
  strings:
    $key_4b0d = { 1c 7f [2] 2e 5d [2] 28 68 [2] 06 68 [2] 39 74 }

  condition:
    any of them
}