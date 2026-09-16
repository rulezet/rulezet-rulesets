rule TTP_XOR_WriteProcessMemory_463f {
  strings:
    $key_463f = { 11 4d [2] 23 6f [2] 25 5a [2] 0b 5a [2] 34 46 }

  condition:
    any of them
}