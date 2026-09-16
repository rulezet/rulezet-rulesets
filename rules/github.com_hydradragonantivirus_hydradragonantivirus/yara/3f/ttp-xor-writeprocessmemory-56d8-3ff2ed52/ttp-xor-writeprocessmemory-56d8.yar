rule TTP_XOR_WriteProcessMemory_56d8 {
  strings:
    $key_56d8 = { 01 aa [2] 33 88 [2] 35 bd [2] 1b bd [2] 24 a1 }

  condition:
    any of them
}