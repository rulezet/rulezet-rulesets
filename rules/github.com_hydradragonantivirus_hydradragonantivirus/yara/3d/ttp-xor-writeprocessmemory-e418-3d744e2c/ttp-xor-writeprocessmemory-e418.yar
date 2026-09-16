rule TTP_XOR_WriteProcessMemory_e418 {
  strings:
    $key_e418 = { b3 6a [2] 81 48 [2] 87 7d [2] a9 7d [2] 96 61 }

  condition:
    any of them
}