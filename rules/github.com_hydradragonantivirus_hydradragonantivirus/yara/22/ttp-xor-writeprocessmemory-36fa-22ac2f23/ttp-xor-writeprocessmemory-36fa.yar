rule TTP_XOR_WriteProcessMemory_36fa {
  strings:
    $key_36fa = { 61 88 [2] 53 aa [2] 55 9f [2] 7b 9f [2] 44 83 }

  condition:
    any of them
}