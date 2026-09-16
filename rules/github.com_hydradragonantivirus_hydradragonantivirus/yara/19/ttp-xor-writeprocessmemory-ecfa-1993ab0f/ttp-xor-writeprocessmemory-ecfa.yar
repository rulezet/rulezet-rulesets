rule TTP_XOR_WriteProcessMemory_ecfa {
  strings:
    $key_ecfa = { bb 88 [2] 89 aa [2] 8f 9f [2] a1 9f [2] 9e 83 }

  condition:
    any of them
}