rule TTP_XOR_WriteProcessMemory_3bfa {
  strings:
    $key_3bfa = { 6c 88 [2] 5e aa [2] 58 9f [2] 76 9f [2] 49 83 }

  condition:
    any of them
}