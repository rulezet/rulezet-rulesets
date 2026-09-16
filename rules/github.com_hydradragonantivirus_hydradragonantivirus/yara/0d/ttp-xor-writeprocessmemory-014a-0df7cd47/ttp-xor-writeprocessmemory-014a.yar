rule TTP_XOR_WriteProcessMemory_014a {
  strings:
    $key_014a = { 56 38 [2] 64 1a [2] 62 2f [2] 4c 2f [2] 73 33 }

  condition:
    any of them
}