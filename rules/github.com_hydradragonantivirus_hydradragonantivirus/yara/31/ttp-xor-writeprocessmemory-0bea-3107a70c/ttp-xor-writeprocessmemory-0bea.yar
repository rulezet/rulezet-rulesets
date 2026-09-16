rule TTP_XOR_WriteProcessMemory_0bea {
  strings:
    $key_0bea = { 5c 98 [2] 6e ba [2] 68 8f [2] 46 8f [2] 79 93 }

  condition:
    any of them
}