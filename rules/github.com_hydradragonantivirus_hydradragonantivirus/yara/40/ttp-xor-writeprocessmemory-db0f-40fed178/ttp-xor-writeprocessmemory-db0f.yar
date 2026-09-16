rule TTP_XOR_WriteProcessMemory_db0f {
  strings:
    $key_db0f = { 8c 7d [2] be 5f [2] b8 6a [2] 96 6a [2] a9 76 }

  condition:
    any of them
}