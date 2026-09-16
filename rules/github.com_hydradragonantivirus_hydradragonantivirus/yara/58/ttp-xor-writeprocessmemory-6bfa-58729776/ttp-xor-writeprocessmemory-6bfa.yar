rule TTP_XOR_WriteProcessMemory_6bfa {
  strings:
    $key_6bfa = { 3c 88 [2] 0e aa [2] 08 9f [2] 26 9f [2] 19 83 }

  condition:
    any of them
}