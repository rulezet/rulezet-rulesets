rule TTP_XOR_WriteProcessMemory_603a {
  strings:
    $key_603a = { 37 48 [2] 05 6a [2] 03 5f [2] 2d 5f [2] 12 43 }

  condition:
    any of them
}