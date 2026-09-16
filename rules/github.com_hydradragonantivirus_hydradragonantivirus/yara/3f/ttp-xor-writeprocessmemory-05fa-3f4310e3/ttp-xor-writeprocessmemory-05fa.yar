rule TTP_XOR_WriteProcessMemory_05fa {
  strings:
    $key_05fa = { 52 88 [2] 60 aa [2] 66 9f [2] 48 9f [2] 77 83 }

  condition:
    any of them
}