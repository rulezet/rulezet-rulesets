rule TTP_XOR_WriteProcessMemory_ece8 {
  strings:
    $key_ece8 = { bb 9a [2] 89 b8 [2] 8f 8d [2] a1 8d [2] 9e 91 }

  condition:
    any of them
}