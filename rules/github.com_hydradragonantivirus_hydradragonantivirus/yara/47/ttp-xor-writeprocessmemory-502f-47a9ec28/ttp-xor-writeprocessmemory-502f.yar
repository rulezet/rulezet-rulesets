rule TTP_XOR_WriteProcessMemory_502f {
  strings:
    $key_502f = { 07 5d [2] 35 7f [2] 33 4a [2] 1d 4a [2] 22 56 }

  condition:
    any of them
}