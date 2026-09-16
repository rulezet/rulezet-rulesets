rule TTP_XOR_WriteProcessMemory_506a {
  strings:
    $key_506a = { 07 18 [2] 35 3a [2] 33 0f [2] 1d 0f [2] 22 13 }

  condition:
    any of them
}