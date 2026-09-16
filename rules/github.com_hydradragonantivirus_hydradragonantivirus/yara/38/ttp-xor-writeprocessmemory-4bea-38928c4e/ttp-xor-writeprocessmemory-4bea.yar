rule TTP_XOR_WriteProcessMemory_4bea {
  strings:
    $key_4bea = { 1c 98 [2] 2e ba [2] 28 8f [2] 06 8f [2] 39 93 }

  condition:
    any of them
}