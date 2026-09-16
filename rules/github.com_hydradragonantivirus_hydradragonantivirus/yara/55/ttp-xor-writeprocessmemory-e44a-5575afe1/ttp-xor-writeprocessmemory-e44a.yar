rule TTP_XOR_WriteProcessMemory_e44a {
  strings:
    $key_e44a = { b3 38 [2] 81 1a [2] 87 2f [2] a9 2f [2] 96 33 }

  condition:
    any of them
}