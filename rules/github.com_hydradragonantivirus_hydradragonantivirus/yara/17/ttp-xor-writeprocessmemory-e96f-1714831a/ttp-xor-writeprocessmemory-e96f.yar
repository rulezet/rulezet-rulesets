rule TTP_XOR_WriteProcessMemory_e96f {
  strings:
    $key_e96f = { be 1d [2] 8c 3f [2] 8a 0a [2] a4 0a [2] 9b 16 }

  condition:
    any of them
}