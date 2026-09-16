rule TTP_XOR_WriteProcessMemory_5dea {
  strings:
    $key_5dea = { 0a 98 [2] 38 ba [2] 3e 8f [2] 10 8f [2] 2f 93 }

  condition:
    any of them
}