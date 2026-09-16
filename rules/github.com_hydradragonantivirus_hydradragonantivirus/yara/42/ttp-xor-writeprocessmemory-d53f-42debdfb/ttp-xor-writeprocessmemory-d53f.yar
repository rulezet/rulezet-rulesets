rule TTP_XOR_WriteProcessMemory_d53f {
  strings:
    $key_d53f = { 82 4d [2] b0 6f [2] b6 5a [2] 98 5a [2] a7 46 }

  condition:
    any of them
}