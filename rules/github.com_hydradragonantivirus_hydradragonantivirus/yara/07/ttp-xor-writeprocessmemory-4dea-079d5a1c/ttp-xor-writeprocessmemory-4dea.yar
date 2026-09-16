rule TTP_XOR_WriteProcessMemory_4dea {
  strings:
    $key_4dea = { 1a 98 [2] 28 ba [2] 2e 8f [2] 00 8f [2] 3f 93 }

  condition:
    any of them
}