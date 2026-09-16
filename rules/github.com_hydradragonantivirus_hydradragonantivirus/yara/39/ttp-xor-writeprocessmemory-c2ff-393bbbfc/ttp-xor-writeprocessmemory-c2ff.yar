rule TTP_XOR_WriteProcessMemory_c2ff {
  strings:
    $key_c2ff = { 95 8d [2] a7 af [2] a1 9a [2] 8f 9a [2] b0 86 }

  condition:
    any of them
}