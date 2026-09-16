rule TTP_XOR_WriteProcessMemory_162f {
  strings:
    $key_162f = { 41 5d [2] 73 7f [2] 75 4a [2] 5b 4a [2] 64 56 }

  condition:
    any of them
}