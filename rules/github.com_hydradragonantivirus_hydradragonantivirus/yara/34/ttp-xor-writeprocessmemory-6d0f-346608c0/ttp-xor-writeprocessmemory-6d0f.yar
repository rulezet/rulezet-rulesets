rule TTP_XOR_WriteProcessMemory_6d0f {
  strings:
    $key_6d0f = { 3a 7d [2] 08 5f [2] 0e 6a [2] 20 6a [2] 1f 76 }

  condition:
    any of them
}