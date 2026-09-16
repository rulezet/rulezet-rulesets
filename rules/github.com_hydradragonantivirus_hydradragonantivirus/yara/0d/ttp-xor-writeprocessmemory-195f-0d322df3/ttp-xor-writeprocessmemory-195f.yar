rule TTP_XOR_WriteProcessMemory_195f {
  strings:
    $key_195f = { 4e 2d [2] 7c 0f [2] 7a 3a [2] 54 3a [2] 6b 26 }

  condition:
    any of them
}