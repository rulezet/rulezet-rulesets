rule TTP_XOR_WriteProcessMemory_004a {
  strings:
    $key_004a = { 57 38 [2] 65 1a [2] 63 2f [2] 4d 2f [2] 72 33 }

  condition:
    any of them
}