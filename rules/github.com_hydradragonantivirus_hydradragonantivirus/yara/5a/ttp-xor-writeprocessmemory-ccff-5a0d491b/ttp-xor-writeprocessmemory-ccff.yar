rule TTP_XOR_WriteProcessMemory_ccff {
  strings:
    $key_ccff = { 9b 8d [2] a9 af [2] af 9a [2] 81 9a [2] be 86 }

  condition:
    any of them
}