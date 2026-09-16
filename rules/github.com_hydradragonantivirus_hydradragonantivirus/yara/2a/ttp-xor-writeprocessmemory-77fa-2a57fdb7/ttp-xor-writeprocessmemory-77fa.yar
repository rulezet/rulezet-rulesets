rule TTP_XOR_WriteProcessMemory_77fa {
  strings:
    $key_77fa = { 20 88 [2] 12 aa [2] 14 9f [2] 3a 9f [2] 05 83 }

  condition:
    any of them
}