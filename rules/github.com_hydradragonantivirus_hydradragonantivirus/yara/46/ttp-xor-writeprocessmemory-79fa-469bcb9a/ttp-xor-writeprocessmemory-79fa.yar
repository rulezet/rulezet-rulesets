rule TTP_XOR_WriteProcessMemory_79fa {
  strings:
    $key_79fa = { 2e 88 [2] 1c aa [2] 1a 9f [2] 34 9f [2] 0b 83 }

  condition:
    any of them
}