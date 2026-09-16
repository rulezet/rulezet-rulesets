rule TTP_XOR_WriteProcessMemory_2cff {
  strings:
    $key_2cff = { 7b 8d [2] 49 af [2] 4f 9a [2] 61 9a [2] 5e 86 }

  condition:
    any of them
}