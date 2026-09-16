rule TTP_XOR_WriteProcessMemory_c7ff {
  strings:
    $key_c7ff = { 90 8d [2] a2 af [2] a4 9a [2] 8a 9a [2] b5 86 }

  condition:
    any of them
}