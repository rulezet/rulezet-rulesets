rule TTP_XOR_WriteProcessMemory_d40f {
  strings:
    $key_d40f = { 83 7d [2] b1 5f [2] b7 6a [2] 99 6a [2] a6 76 }

  condition:
    any of them
}