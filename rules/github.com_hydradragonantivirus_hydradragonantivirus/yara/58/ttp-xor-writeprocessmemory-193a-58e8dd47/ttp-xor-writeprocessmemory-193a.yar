rule TTP_XOR_WriteProcessMemory_193a {
  strings:
    $key_193a = { 4e 48 [2] 7c 6a [2] 7a 5f [2] 54 5f [2] 6b 43 }

  condition:
    any of them
}