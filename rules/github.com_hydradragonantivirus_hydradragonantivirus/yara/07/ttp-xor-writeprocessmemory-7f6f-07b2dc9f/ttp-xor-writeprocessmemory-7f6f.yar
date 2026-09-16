rule TTP_XOR_WriteProcessMemory_7f6f {
  strings:
    $key_7f6f = { 28 1d [2] 1a 3f [2] 1c 0a [2] 32 0a [2] 0d 16 }

  condition:
    any of them
}