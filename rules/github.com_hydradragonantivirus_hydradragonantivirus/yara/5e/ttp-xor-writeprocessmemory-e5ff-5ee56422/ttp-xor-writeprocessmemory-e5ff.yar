rule TTP_XOR_WriteProcessMemory_e5ff {
  strings:
    $key_e5ff = { b2 8d [2] 80 af [2] 86 9a [2] a8 9a [2] 97 86 }

  condition:
    any of them
}