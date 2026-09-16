rule TTP_XOR_WriteProcessMemory_2e6a {
  strings:
    $key_2e6a = { 79 18 [2] 4b 3a [2] 4d 0f [2] 63 0f [2] 5c 13 }

  condition:
    any of them
}