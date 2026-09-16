rule TTP_XOR_WriteProcessMemory_6d7a {
  strings:
    $key_6d7a = { 3a 08 [2] 08 2a [2] 0e 1f [2] 20 1f [2] 1f 03 }

  condition:
    any of them
}