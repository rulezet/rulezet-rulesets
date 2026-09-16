rule TTP_XOR_WriteProcessMemory_69fa {
  strings:
    $key_69fa = { 3e 88 [2] 0c aa [2] 0a 9f [2] 24 9f [2] 1b 83 }

  condition:
    any of them
}