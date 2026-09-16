rule TTP_XOR_WriteProcessMemory_e40f {
  strings:
    $key_e40f = { b3 7d [2] 81 5f [2] 87 6a [2] a9 6a [2] 96 76 }

  condition:
    any of them
}