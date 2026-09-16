rule TTP_XOR_WriteProcessMemory_e83a {
  strings:
    $key_e83a = { bf 48 [2] 8d 6a [2] 8b 5f [2] a5 5f [2] 9a 43 }

  condition:
    any of them
}