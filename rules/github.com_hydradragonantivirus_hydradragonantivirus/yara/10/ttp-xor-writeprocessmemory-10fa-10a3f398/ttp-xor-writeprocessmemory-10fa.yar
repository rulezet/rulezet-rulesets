rule TTP_XOR_WriteProcessMemory_10fa {
  strings:
    $key_10fa = { 47 88 [2] 75 aa [2] 73 9f [2] 5d 9f [2] 62 83 }

  condition:
    any of them
}