rule TTP_XOR_WriteProcessMemory_3b1f {
  strings:
    $key_3b1f = { 6c 6d [2] 5e 4f [2] 58 7a [2] 76 7a [2] 49 66 }

  condition:
    any of them
}