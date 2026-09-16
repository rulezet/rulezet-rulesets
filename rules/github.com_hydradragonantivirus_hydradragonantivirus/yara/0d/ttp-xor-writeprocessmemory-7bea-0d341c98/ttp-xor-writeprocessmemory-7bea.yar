rule TTP_XOR_WriteProcessMemory_7bea {
  strings:
    $key_7bea = { 2c 98 [2] 1e ba [2] 18 8f [2] 36 8f [2] 09 93 }

  condition:
    any of them
}