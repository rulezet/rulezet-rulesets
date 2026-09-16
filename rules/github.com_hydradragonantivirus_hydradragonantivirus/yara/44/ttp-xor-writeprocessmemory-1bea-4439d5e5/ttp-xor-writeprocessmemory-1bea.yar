rule TTP_XOR_WriteProcessMemory_1bea {
  strings:
    $key_1bea = { 4c 98 [2] 7e ba [2] 78 8f [2] 56 8f [2] 69 93 }

  condition:
    any of them
}