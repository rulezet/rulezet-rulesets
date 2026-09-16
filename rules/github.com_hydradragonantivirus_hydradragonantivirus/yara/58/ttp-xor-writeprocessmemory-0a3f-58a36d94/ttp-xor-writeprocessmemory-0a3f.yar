rule TTP_XOR_WriteProcessMemory_0a3f {
  strings:
    $key_0a3f = { 5d 4d [2] 6f 6f [2] 69 5a [2] 47 5a [2] 78 46 }

  condition:
    any of them
}