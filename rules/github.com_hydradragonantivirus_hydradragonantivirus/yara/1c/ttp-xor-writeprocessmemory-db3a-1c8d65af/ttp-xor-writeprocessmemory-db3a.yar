rule TTP_XOR_WriteProcessMemory_db3a {
  strings:
    $key_db3a = { 8c 48 [2] be 6a [2] b8 5f [2] 96 5f [2] a9 43 }

  condition:
    any of them
}