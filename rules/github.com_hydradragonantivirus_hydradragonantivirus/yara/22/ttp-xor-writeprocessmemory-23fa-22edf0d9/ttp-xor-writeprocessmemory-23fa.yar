rule TTP_XOR_WriteProcessMemory_23fa {
  strings:
    $key_23fa = { 74 88 [2] 46 aa [2] 40 9f [2] 6e 9f [2] 51 83 }

  condition:
    any of them
}