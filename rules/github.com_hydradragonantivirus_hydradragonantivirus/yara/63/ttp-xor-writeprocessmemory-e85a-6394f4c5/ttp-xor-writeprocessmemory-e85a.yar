rule TTP_XOR_WriteProcessMemory_e85a {
  strings:
    $key_e85a = { bf 28 [2] 8d 0a [2] 8b 3f [2] a5 3f [2] 9a 23 }

  condition:
    any of them
}