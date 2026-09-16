rule TTP_XOR_WriteProcessMemory_285f {
  strings:
    $key_285f = { 7f 2d [2] 4d 0f [2] 4b 3a [2] 65 3a [2] 5a 26 }

  condition:
    any of them
}