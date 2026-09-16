rule TTP_XOR_WriteProcessMemory_4bfa {
  strings:
    $key_4bfa = { 1c 88 [2] 2e aa [2] 28 9f [2] 06 9f [2] 39 83 }

  condition:
    any of them
}