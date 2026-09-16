rule TTP_XOR_WriteProcessMemory_0c6a {
  strings:
    $key_0c6a = { 5b 18 [2] 69 3a [2] 6f 0f [2] 41 0f [2] 7e 13 }

  condition:
    any of them
}