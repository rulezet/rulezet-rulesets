rule TTP_XOR_WriteProcessMemory_7f3f {
  strings:
    $key_7f3f = { 28 4d [2] 1a 6f [2] 1c 5a [2] 32 5a [2] 0d 46 }

  condition:
    any of them
}