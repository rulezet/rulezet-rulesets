rule TTP_XOR_WriteProcessMemory_42fa {
  strings:
    $key_42fa = { 15 88 [2] 27 aa [2] 21 9f [2] 0f 9f [2] 30 83 }

  condition:
    any of them
}