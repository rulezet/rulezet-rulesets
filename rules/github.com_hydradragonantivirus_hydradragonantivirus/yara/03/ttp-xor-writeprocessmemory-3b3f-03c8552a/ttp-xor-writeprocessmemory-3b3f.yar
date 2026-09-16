rule TTP_XOR_WriteProcessMemory_3b3f {
  strings:
    $key_3b3f = { 6c 4d [2] 5e 6f [2] 58 5a [2] 76 5a [2] 49 46 }

  condition:
    any of them
}