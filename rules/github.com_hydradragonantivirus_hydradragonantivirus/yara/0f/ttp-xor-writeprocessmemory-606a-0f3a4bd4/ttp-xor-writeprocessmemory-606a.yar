rule TTP_XOR_WriteProcessMemory_606a {
  strings:
    $key_606a = { 37 18 [2] 05 3a [2] 03 0f [2] 2d 0f [2] 12 13 }

  condition:
    any of them
}