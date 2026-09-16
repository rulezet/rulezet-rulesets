rule TTP_XOR_WriteProcessMemory_5228 {
  strings:
    $key_5228 = { 05 5a [2] 37 78 [2] 31 4d [2] 1f 4d [2] 20 51 }

  condition:
    any of them
}