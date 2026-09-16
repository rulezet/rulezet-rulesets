rule TTP_XOR_WriteProcessMemory_0d7f {
  strings:
    $key_0d7f = { 5a 0d [2] 68 2f [2] 6e 1a [2] 40 1a [2] 7f 06 }

  condition:
    any of them
}