rule TTP_XOR_WriteProcessMemory_5ffa {
  strings:
    $key_5ffa = { 08 88 [2] 3a aa [2] 3c 9f [2] 12 9f [2] 2d 83 }

  condition:
    any of them
}