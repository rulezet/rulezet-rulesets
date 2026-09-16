rule TTP_XOR_WriteProcessMemory_0c3a {
  strings:
    $key_0c3a = { 5b 48 [2] 69 6a [2] 6f 5f [2] 41 5f [2] 7e 43 }

  condition:
    any of them
}