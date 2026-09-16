rule TTP_XOR_WriteProcessMemory_56fa {
  strings:
    $key_56fa = { 01 88 [2] 33 aa [2] 35 9f [2] 1b 9f [2] 24 83 }

  condition:
    any of them
}