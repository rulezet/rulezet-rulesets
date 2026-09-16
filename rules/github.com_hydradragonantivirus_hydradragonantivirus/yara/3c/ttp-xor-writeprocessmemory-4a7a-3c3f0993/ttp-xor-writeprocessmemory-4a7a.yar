rule TTP_XOR_WriteProcessMemory_4a7a {
  strings:
    $key_4a7a = { 1d 08 [2] 2f 2a [2] 29 1f [2] 07 1f [2] 38 03 }

  condition:
    any of them
}