rule TTP_XOR_WriteProcessMemory_ebff {
  strings:
    $key_ebff = { bc 8d [2] 8e af [2] 88 9a [2] a6 9a [2] 99 86 }

  condition:
    any of them
}