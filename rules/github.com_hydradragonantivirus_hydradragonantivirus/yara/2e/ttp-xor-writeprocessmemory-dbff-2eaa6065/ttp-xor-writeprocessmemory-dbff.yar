rule TTP_XOR_WriteProcessMemory_dbff {
  strings:
    $key_dbff = { 8c 8d [2] be af [2] b8 9a [2] 96 9a [2] a9 86 }

  condition:
    any of them
}