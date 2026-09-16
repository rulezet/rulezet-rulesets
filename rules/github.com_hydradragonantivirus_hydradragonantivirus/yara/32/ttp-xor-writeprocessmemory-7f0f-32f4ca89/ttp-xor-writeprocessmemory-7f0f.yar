rule TTP_XOR_WriteProcessMemory_7f0f {
  strings:
    $key_7f0f = { 28 7d [2] 1a 5f [2] 1c 6a [2] 32 6a [2] 0d 76 }

  condition:
    any of them
}