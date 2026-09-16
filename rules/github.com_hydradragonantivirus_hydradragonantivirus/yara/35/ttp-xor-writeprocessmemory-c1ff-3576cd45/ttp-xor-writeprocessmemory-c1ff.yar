rule TTP_XOR_WriteProcessMemory_c1ff {
  strings:
    $key_c1ff = { 96 8d [2] a4 af [2] a2 9a [2] 8c 9a [2] b3 86 }

  condition:
    any of them
}