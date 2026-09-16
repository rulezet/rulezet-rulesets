rule TTP_XOR_WriteProcessMemory_4eea {
  strings:
    $key_4eea = { 19 98 [2] 2b ba [2] 2d 8f [2] 03 8f [2] 3c 93 }

  condition:
    any of them
}