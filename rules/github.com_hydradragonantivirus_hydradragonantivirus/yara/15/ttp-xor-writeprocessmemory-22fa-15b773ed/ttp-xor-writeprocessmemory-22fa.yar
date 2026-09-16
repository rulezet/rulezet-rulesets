rule TTP_XOR_WriteProcessMemory_22fa {
  strings:
    $key_22fa = { 75 88 [2] 47 aa [2] 41 9f [2] 6f 9f [2] 50 83 }

  condition:
    any of them
}