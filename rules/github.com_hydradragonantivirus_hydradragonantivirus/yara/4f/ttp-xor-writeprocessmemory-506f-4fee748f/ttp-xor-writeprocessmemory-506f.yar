rule TTP_XOR_WriteProcessMemory_506f {
  strings:
    $key_506f = { 07 1d [2] 35 3f [2] 33 0a [2] 1d 0a [2] 22 16 }

  condition:
    any of them
}