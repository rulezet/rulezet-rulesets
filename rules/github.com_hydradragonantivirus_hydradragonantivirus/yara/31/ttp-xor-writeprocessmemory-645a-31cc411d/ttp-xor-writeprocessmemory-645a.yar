rule TTP_XOR_WriteProcessMemory_645a {
  strings:
    $key_645a = { 33 28 [2] 01 0a [2] 07 3f [2] 29 3f [2] 16 23 }

  condition:
    any of them
}