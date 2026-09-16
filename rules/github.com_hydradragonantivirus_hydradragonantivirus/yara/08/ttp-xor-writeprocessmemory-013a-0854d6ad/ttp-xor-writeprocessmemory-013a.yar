rule TTP_XOR_WriteProcessMemory_013a {
  strings:
    $key_013a = { 56 48 [2] 64 6a [2] 62 5f [2] 4c 5f [2] 73 43 }

  condition:
    any of them
}