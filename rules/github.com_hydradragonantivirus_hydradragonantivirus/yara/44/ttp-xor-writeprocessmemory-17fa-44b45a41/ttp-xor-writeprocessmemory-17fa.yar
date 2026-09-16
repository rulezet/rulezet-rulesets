rule TTP_XOR_WriteProcessMemory_17fa {
  strings:
    $key_17fa = { 40 88 [2] 72 aa [2] 74 9f [2] 5a 9f [2] 65 83 }

  condition:
    any of them
}