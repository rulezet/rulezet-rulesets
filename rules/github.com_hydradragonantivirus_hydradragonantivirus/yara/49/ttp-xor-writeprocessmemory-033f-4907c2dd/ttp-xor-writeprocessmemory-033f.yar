rule TTP_XOR_WriteProcessMemory_033f {
  strings:
    $key_033f = { 54 4d [2] 66 6f [2] 60 5a [2] 4e 5a [2] 71 46 }

  condition:
    any of them
}