rule TTP_XOR_WriteProcessMemory_f52f {
  strings:
    $key_f52f = { a2 5d [2] 90 7f [2] 96 4a [2] b8 4a [2] 87 56 }

  condition:
    any of them
}