rule TTP_XOR_WriteProcessMemory_d8fa {
  strings:
    $key_d8fa = { 8f 88 [2] bd aa [2] bb 9f [2] 95 9f [2] aa 83 }

  condition:
    any of them
}