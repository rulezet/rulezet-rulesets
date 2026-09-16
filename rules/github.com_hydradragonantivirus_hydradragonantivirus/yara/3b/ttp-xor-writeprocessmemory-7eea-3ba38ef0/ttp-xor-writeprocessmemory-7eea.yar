rule TTP_XOR_WriteProcessMemory_7eea {
  strings:
    $key_7eea = { 29 98 [2] 1b ba [2] 1d 8f [2] 33 8f [2] 0c 93 }

  condition:
    any of them
}