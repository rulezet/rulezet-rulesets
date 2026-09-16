rule TTP_XOR_WriteProcessMemory_230a {
  strings:
    $key_230a = { 74 78 [2] 46 5a [2] 40 6f [2] 6e 6f [2] 51 73 }

  condition:
    any of them
}