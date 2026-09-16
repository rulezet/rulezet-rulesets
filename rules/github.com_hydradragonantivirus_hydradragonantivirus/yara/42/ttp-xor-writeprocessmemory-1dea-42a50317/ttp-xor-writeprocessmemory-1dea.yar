rule TTP_XOR_WriteProcessMemory_1dea {
  strings:
    $key_1dea = { 4a 98 [2] 78 ba [2] 7e 8f [2] 50 8f [2] 6f 93 }

  condition:
    any of them
}