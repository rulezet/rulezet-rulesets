rule TTP_XOR_WriteProcessMemory_f53f {
  strings:
    $key_f53f = { a2 4d [2] 90 6f [2] 96 5a [2] b8 5a [2] 87 46 }

  condition:
    any of them
}