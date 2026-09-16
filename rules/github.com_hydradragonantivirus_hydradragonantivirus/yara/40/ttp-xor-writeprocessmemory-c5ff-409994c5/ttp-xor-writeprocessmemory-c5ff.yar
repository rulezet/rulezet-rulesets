rule TTP_XOR_WriteProcessMemory_c5ff {
  strings:
    $key_c5ff = { 92 8d [2] a0 af [2] a6 9a [2] 88 9a [2] b7 86 }

  condition:
    any of them
}