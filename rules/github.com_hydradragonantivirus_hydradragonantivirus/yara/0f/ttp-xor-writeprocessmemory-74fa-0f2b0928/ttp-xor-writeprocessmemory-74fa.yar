rule TTP_XOR_WriteProcessMemory_74fa {
  strings:
    $key_74fa = { 23 88 [2] 11 aa [2] 17 9f [2] 39 9f [2] 06 83 }

  condition:
    any of them
}