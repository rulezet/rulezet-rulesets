rule TTP_XOR_WriteProcessMemory_e8ff {
  strings:
    $key_e8ff = { bf 8d [2] 8d af [2] 8b 9a [2] a5 9a [2] 9a 86 }

  condition:
    any of them
}