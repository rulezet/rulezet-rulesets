rule TTP_XOR_WriteProcessMemory_112a {
  strings:
    $key_112a = { 46 58 [2] 74 7a [2] 72 4f [2] 5c 4f [2] 63 53 }

  condition:
    any of them
}