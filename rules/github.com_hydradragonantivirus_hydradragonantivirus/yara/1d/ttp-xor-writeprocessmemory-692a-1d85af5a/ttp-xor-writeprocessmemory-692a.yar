rule TTP_XOR_WriteProcessMemory_692a {
  strings:
    $key_692a = { 3e 58 [2] 0c 7a [2] 0a 4f [2] 24 4f [2] 1b 53 }

  condition:
    any of them
}