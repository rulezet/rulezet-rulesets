rule TTP_XOR_WriteProcessMemory_ebea {
  strings:
    $key_ebea = { bc 98 [2] 8e ba [2] 88 8f [2] a6 8f [2] 99 93 }

  condition:
    any of them
}