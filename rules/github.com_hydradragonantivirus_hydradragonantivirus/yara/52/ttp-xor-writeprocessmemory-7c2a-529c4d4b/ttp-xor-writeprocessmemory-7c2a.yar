rule TTP_XOR_WriteProcessMemory_7c2a {
  strings:
    $key_7c2a = { 2b 58 [2] 19 7a [2] 1f 4f [2] 31 4f [2] 0e 53 }

  condition:
    any of them
}