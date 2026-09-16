rule TTP_XOR_WriteProcessMemory_07fa {
  strings:
    $key_07fa = { 50 88 [2] 62 aa [2] 64 9f [2] 4a 9f [2] 75 83 }

  condition:
    any of them
}