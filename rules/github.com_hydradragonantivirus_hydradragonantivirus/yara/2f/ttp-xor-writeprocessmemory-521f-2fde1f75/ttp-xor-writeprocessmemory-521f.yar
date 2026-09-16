rule TTP_XOR_WriteProcessMemory_521f {
  strings:
    $key_521f = { 05 6d [2] 37 4f [2] 31 7a [2] 1f 7a [2] 20 66 }

  condition:
    any of them
}