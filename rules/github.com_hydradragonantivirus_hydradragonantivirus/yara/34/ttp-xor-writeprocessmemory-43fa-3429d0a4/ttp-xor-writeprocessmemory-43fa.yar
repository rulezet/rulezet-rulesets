rule TTP_XOR_WriteProcessMemory_43fa {
  strings:
    $key_43fa = { 14 88 [2] 26 aa [2] 20 9f [2] 0e 9f [2] 31 83 }

  condition:
    any of them
}