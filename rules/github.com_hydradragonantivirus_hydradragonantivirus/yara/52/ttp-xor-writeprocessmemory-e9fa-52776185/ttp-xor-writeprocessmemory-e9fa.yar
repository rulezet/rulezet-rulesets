rule TTP_XOR_WriteProcessMemory_e9fa {
  strings:
    $key_e9fa = { be 88 [2] 8c aa [2] 8a 9f [2] a4 9f [2] 9b 83 }

  condition:
    any of them
}