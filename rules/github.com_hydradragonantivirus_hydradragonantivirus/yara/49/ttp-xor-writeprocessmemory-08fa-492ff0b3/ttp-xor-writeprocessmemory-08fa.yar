rule TTP_XOR_WriteProcessMemory_08fa {
  strings:
    $key_08fa = { 5f 88 [2] 6d aa [2] 6b 9f [2] 45 9f [2] 7a 83 }

  condition:
    any of them
}