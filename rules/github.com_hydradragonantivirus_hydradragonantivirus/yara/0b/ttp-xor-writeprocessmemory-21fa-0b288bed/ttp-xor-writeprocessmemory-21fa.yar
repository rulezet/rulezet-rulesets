rule TTP_XOR_WriteProcessMemory_21fa {
  strings:
    $key_21fa = { 76 88 [2] 44 aa [2] 42 9f [2] 6c 9f [2] 53 83 }

  condition:
    any of them
}