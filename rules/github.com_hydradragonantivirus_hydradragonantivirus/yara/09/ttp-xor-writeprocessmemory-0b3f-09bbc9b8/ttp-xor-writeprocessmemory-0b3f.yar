rule TTP_XOR_WriteProcessMemory_0b3f {
  strings:
    $key_0b3f = { 5c 4d [2] 6e 6f [2] 68 5a [2] 46 5a [2] 79 46 }

  condition:
    any of them
}