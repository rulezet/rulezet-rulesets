rule TTP_XOR_WriteProcessMemory_71fa {
  strings:
    $key_71fa = { 26 88 [2] 14 aa [2] 12 9f [2] 3c 9f [2] 03 83 }

  condition:
    any of them
}