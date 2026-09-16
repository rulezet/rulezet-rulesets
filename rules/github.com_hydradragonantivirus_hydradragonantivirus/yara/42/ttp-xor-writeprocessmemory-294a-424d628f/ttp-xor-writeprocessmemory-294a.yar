rule TTP_XOR_WriteProcessMemory_294a {
  strings:
    $key_294a = { 7e 38 [2] 4c 1a [2] 4a 2f [2] 64 2f [2] 5b 33 }

  condition:
    any of them
}