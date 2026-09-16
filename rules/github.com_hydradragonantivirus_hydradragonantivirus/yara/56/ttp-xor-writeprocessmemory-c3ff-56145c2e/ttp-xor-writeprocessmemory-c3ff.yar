rule TTP_XOR_WriteProcessMemory_c3ff {
  strings:
    $key_c3ff = { 94 8d [2] a6 af [2] a0 9a [2] 8e 9a [2] b1 86 }

  condition:
    any of them
}