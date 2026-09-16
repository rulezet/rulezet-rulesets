rule TTP_XOR_WriteProcessMemory_3a7a {
  strings:
    $key_3a7a = { 6d 08 [2] 5f 2a [2] 59 1f [2] 77 1f [2] 48 03 }

  condition:
    any of them
}