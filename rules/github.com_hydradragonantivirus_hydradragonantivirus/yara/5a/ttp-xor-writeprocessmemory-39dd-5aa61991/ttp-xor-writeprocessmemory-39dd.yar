rule TTP_XOR_WriteProcessMemory_39dd {
  strings:
    $key_39dd = { 6e af [2] 5c 8d [2] 5a b8 [2] 74 b8 [2] 4b a4 }

  condition:
    any of them
}