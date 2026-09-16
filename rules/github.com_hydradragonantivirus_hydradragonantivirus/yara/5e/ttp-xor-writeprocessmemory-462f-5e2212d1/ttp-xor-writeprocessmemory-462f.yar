rule TTP_XOR_WriteProcessMemory_462f {
  strings:
    $key_462f = { 11 5d [2] 23 7f [2] 25 4a [2] 0b 4a [2] 34 56 }

  condition:
    any of them
}