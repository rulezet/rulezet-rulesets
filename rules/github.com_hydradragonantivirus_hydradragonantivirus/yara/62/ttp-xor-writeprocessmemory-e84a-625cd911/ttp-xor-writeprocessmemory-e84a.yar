rule TTP_XOR_WriteProcessMemory_e84a {
  strings:
    $key_e84a = { bf 38 [2] 8d 1a [2] 8b 2f [2] a5 2f [2] 9a 33 }

  condition:
    any of them
}