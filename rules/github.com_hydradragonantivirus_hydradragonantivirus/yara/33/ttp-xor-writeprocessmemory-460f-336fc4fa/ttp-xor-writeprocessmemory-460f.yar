rule TTP_XOR_WriteProcessMemory_460f {
  strings:
    $key_460f = { 11 7d [2] 23 5f [2] 25 6a [2] 0b 6a [2] 34 76 }

  condition:
    any of them
}