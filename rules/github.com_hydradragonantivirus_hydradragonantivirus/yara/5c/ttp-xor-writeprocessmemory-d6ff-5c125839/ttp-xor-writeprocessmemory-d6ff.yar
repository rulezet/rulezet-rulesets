rule TTP_XOR_WriteProcessMemory_d6ff {
  strings:
    $key_d6ff = { 81 8d [2] b3 af [2] b5 9a [2] 9b 9a [2] a4 86 }

  condition:
    any of them
}