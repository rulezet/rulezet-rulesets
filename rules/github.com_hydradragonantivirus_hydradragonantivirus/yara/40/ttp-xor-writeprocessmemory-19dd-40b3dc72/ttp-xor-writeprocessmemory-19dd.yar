rule TTP_XOR_WriteProcessMemory_19dd {
  strings:
    $key_19dd = { 4e af [2] 7c 8d [2] 7a b8 [2] 54 b8 [2] 6b a4 }

  condition:
    any of them
}