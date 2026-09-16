rule TTP_XOR_WriteProcessMemory_2dea {
  strings:
    $key_2dea = { 7a 98 [2] 48 ba [2] 4e 8f [2] 60 8f [2] 5f 93 }

  condition:
    any of them
}