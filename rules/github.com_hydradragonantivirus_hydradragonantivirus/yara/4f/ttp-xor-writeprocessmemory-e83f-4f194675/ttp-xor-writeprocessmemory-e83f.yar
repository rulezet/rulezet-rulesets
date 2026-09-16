rule TTP_XOR_WriteProcessMemory_e83f {
  strings:
    $key_e83f = { bf 4d [2] 8d 6f [2] 8b 5a [2] a5 5a [2] 9a 46 }

  condition:
    any of them
}