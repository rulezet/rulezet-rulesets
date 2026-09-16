rule TTP_XOR_WriteProcessMemory_e9dd {
  strings:
    $key_e9dd = { be af [2] 8c 8d [2] 8a b8 [2] a4 b8 [2] 9b a4 }

  condition:
    any of them
}