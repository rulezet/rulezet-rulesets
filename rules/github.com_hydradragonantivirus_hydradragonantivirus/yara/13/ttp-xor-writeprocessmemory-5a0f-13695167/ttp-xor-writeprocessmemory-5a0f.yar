rule TTP_XOR_WriteProcessMemory_5a0f {
  strings:
    $key_5a0f = { 0d 7d [2] 3f 5f [2] 39 6a [2] 17 6a [2] 28 76 }

  condition:
    any of them
}