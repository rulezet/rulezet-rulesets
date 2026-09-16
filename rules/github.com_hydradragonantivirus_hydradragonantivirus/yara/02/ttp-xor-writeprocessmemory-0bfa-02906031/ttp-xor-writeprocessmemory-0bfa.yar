rule TTP_XOR_WriteProcessMemory_0bfa {
  strings:
    $key_0bfa = { 5c 88 [2] 6e aa [2] 68 9f [2] 46 9f [2] 79 83 }

  condition:
    any of them
}