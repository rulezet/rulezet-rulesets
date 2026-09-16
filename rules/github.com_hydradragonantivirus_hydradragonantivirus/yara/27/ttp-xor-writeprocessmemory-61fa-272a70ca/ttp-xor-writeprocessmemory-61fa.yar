rule TTP_XOR_WriteProcessMemory_61fa {
  strings:
    $key_61fa = { 36 88 [2] 04 aa [2] 02 9f [2] 2c 9f [2] 13 83 }

  condition:
    any of them
}