rule TTP_XOR_WriteProcessMemory_2d7a {
  strings:
    $key_2d7a = { 7a 08 [2] 48 2a [2] 4e 1f [2] 60 1f [2] 5f 03 }

  condition:
    any of them
}