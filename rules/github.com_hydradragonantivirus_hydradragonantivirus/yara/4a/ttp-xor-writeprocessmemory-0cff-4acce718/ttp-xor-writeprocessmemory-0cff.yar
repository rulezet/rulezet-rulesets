rule TTP_XOR_WriteProcessMemory_0cff {
  strings:
    $key_0cff = { 5b 8d [2] 69 af [2] 6f 9a [2] 41 9a [2] 7e 86 }

  condition:
    any of them
}