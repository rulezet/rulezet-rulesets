rule TTP_XOR_WriteProcessMemory_f55f {
  strings:
    $key_f55f = { a2 2d [2] 90 0f [2] 96 3a [2] b8 3a [2] 87 26 }

  condition:
    any of them
}