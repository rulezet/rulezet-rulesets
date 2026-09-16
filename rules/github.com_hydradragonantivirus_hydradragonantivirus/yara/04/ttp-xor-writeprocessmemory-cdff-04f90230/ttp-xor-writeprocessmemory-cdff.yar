rule TTP_XOR_WriteProcessMemory_cdff {
  strings:
    $key_cdff = { 9a 8d [2] a8 af [2] ae 9a [2] 80 9a [2] bf 86 }

  condition:
    any of them
}