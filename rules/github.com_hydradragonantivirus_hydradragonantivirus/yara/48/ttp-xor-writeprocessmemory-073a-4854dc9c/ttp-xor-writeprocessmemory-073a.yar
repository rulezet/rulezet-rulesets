rule TTP_XOR_WriteProcessMemory_073a {
  strings:
    $key_073a = { 50 48 [2] 62 6a [2] 64 5f [2] 4a 5f [2] 75 43 }

  condition:
    any of them
}