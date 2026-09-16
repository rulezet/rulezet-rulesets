rule TTP_XOR_WriteProcessMemory_213a {
  strings:
    $key_213a = { 76 48 [2] 44 6a [2] 42 5f [2] 6c 5f [2] 53 43 }

  condition:
    any of them
}