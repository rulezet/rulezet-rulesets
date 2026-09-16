rule TTP_XOR_WriteProcessMemory_483f {
  strings:
    $key_483f = { 1f 4d [2] 2d 6f [2] 2b 5a [2] 05 5a [2] 3a 46 }

  condition:
    any of them
}