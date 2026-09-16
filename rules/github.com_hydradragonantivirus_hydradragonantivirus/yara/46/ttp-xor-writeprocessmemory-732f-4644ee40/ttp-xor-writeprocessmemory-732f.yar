rule TTP_XOR_WriteProcessMemory_732f {
  strings:
    $key_732f = { 24 5d [2] 16 7f [2] 10 4a [2] 3e 4a [2] 01 56 }

  condition:
    any of them
}