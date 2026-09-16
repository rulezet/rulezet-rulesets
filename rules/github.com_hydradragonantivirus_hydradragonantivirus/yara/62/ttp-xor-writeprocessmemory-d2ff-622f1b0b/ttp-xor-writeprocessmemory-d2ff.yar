rule TTP_XOR_WriteProcessMemory_d2ff {
  strings:
    $key_d2ff = { 85 8d [2] b7 af [2] b1 9a [2] 9f 9a [2] a0 86 }

  condition:
    any of them
}