rule TTP_XOR_WriteProcessMemory_2e1a {
  strings:
    $key_2e1a = { 79 68 [2] 4b 4a [2] 4d 7f [2] 63 7f [2] 5c 63 }

  condition:
    any of them
}