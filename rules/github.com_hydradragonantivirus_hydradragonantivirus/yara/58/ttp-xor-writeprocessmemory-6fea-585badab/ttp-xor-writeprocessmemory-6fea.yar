rule TTP_XOR_WriteProcessMemory_6fea {
  strings:
    $key_6fea = { 38 98 [2] 0a ba [2] 0c 8f [2] 22 8f [2] 1d 93 }

  condition:
    any of them
}