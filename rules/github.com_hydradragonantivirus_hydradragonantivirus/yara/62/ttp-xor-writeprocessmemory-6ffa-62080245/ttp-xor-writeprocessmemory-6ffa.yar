rule TTP_XOR_WriteProcessMemory_6ffa {
  strings:
    $key_6ffa = { 38 88 [2] 0a aa [2] 0c 9f [2] 22 9f [2] 1d 83 }

  condition:
    any of them
}