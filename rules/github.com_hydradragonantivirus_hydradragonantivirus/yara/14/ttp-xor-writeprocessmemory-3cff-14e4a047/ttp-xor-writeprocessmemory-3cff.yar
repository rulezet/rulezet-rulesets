rule TTP_XOR_WriteProcessMemory_3cff {
  strings:
    $key_3cff = { 6b 8d [2] 59 af [2] 5f 9a [2] 71 9a [2] 4e 86 }

  condition:
    any of them
}