rule TTP_XOR_WriteProcessMemory_0c7f {
  strings:
    $key_0c7f = { 5b 0d [2] 69 2f [2] 6f 1a [2] 41 1a [2] 7e 06 }

  condition:
    any of them
}