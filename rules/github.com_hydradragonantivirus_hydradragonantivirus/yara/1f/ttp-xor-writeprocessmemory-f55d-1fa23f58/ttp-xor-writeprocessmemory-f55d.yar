rule TTP_XOR_WriteProcessMemory_f55d {
  strings:
    $key_f55d = { a2 2f [2] 90 0d [2] 96 38 [2] b8 38 [2] 87 24 }

  condition:
    any of them
}