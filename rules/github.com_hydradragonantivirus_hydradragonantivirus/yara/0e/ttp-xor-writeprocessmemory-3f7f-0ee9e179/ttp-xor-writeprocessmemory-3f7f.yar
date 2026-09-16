rule TTP_XOR_WriteProcessMemory_3f7f {
  strings:
    $key_3f7f = { 68 0d [2] 5a 2f [2] 5c 1a [2] 72 1a [2] 4d 06 }

  condition:
    any of them
}