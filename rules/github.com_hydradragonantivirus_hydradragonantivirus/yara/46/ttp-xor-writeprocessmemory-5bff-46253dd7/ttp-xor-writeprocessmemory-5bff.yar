rule TTP_XOR_WriteProcessMemory_5bff {
  strings:
    $key_5bff = { 0c 8d [2] 3e af [2] 38 9a [2] 16 9a [2] 29 86 }

  condition:
    any of them
}