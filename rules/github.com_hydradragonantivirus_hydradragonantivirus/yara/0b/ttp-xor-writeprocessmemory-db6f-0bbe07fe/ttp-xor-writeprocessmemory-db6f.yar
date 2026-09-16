rule TTP_XOR_WriteProcessMemory_db6f {
  strings:
    $key_db6f = { 8c 1d [2] be 3f [2] b8 0a [2] 96 0a [2] a9 16 }

  condition:
    any of them
}