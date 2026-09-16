rule TTP_XOR_WriteProcessMemory_720a {
  strings:
    $key_720a = { 25 78 [2] 17 5a [2] 11 6f [2] 3f 6f [2] 00 73 }

  condition:
    any of them
}