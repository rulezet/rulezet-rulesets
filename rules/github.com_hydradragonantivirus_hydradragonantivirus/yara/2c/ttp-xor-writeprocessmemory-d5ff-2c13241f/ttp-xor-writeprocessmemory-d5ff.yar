rule TTP_XOR_WriteProcessMemory_d5ff {
  strings:
    $key_d5ff = { 82 8d [2] b0 af [2] b6 9a [2] 98 9a [2] a7 86 }

  condition:
    any of them
}