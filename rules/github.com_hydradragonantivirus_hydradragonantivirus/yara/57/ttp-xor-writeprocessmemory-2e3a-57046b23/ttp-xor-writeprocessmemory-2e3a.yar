rule TTP_XOR_WriteProcessMemory_2e3a {
  strings:
    $key_2e3a = { 79 48 [2] 4b 6a [2] 4d 5f [2] 63 5f [2] 5c 43 }

  condition:
    any of them
}