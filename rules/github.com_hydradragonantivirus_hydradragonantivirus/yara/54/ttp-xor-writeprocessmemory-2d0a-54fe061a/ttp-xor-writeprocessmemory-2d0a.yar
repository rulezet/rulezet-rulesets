rule TTP_XOR_WriteProcessMemory_2d0a {
  strings:
    $key_2d0a = { 7a 78 [2] 48 5a [2] 4e 6f [2] 60 6f [2] 5f 73 }

  condition:
    any of them
}