rule TTP_XOR_WriteProcessMemory_33fa {
  strings:
    $key_33fa = { 64 88 [2] 56 aa [2] 50 9f [2] 7e 9f [2] 41 83 }

  condition:
    any of them
}