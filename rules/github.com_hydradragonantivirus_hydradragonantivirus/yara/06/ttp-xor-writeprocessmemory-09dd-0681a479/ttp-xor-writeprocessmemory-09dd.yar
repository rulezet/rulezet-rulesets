rule TTP_XOR_WriteProcessMemory_09dd {
  strings:
    $key_09dd = { 5e af [2] 6c 8d [2] 6a b8 [2] 44 b8 [2] 7b a4 }

  condition:
    any of them
}