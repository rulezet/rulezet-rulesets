rule TTP_XOR_WriteProcessMemory_ca68 {
  strings:
    $key_ca68 = { 9d 1a [2] af 38 [2] a9 0d [2] 87 0d [2] b8 11 }

  condition:
    any of them
}