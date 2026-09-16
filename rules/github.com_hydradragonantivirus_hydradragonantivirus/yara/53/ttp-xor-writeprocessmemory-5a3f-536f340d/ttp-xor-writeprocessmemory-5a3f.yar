rule TTP_XOR_WriteProcessMemory_5a3f {
  strings:
    $key_5a3f = { 0d 4d [2] 3f 6f [2] 39 5a [2] 17 5a [2] 28 46 }

  condition:
    any of them
}