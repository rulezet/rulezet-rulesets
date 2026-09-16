rule TTP_XOR_WriteProcessMemory_e86a {
  strings:
    $key_e86a = { bf 18 [2] 8d 3a [2] 8b 0f [2] a5 0f [2] 9a 13 }

  condition:
    any of them
}