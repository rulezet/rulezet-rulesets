rule TTP_XOR_WriteProcessMemory_6dff {
  strings:
    $key_6dff = { 3a 8d [2] 08 af [2] 0e 9a [2] 20 9a [2] 1f 86 }

  condition:
    any of them
}