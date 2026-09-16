rule TTP_XOR_WriteProcessMemory_5fea {
  strings:
    $key_5fea = { 08 98 [2] 3a ba [2] 3c 8f [2] 12 8f [2] 2d 93 }

  condition:
    any of them
}