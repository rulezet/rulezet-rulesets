rule TTP_XOR_WriteProcessMemory_103f {
  strings:
    $key_103f = { 47 4d [2] 75 6f [2] 73 5a [2] 5d 5a [2] 62 46 }

  condition:
    any of them
}