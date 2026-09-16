rule TTP_XOR_WriteProcessMemory_3bff {
  strings:
    $key_3bff = { 6c 8d [2] 5e af [2] 58 9a [2] 76 9a [2] 49 86 }

  condition:
    any of them
}