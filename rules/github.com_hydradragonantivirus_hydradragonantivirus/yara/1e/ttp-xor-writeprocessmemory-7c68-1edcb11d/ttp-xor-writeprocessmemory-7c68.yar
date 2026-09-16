rule TTP_XOR_WriteProcessMemory_7c68 {
  strings:
    $key_7c68 = { 2b 1a [2] 19 38 [2] 1f 0d [2] 31 0d [2] 0e 11 }

  condition:
    any of them
}