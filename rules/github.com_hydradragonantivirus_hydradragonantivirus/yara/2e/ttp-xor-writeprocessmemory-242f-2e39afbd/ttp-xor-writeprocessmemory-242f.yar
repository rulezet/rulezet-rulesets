rule TTP_XOR_WriteProcessMemory_242f {
  strings:
    $key_242f = { 73 5d [2] 41 7f [2] 47 4a [2] 69 4a [2] 56 56 }

  condition:
    any of them
}