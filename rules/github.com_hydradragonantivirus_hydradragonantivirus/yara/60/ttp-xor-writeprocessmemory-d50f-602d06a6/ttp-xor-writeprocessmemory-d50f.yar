rule TTP_XOR_WriteProcessMemory_d50f {
  strings:
    $key_d50f = { 82 7d [2] b0 5f [2] b6 6a [2] 98 6a [2] a7 76 }

  condition:
    any of them
}