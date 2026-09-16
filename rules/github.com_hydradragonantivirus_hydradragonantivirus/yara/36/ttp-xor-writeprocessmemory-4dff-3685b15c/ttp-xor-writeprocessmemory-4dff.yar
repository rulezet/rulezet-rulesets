rule TTP_XOR_WriteProcessMemory_4dff {
  strings:
    $key_4dff = { 1a 8d [2] 28 af [2] 2e 9a [2] 00 9a [2] 3f 86 }

  condition:
    any of them
}