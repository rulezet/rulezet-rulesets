rule TTP_XOR_WriteProcessMemory_c6ff {
  strings:
    $key_c6ff = { 91 8d [2] a3 af [2] a5 9a [2] 8b 9a [2] b4 86 }

  condition:
    any of them
}