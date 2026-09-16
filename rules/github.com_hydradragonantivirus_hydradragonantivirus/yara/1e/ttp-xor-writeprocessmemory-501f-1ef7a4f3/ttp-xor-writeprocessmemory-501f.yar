rule TTP_XOR_WriteProcessMemory_501f {
  strings:
    $key_501f = { 07 6d [2] 35 4f [2] 33 7a [2] 1d 7a [2] 22 66 }

  condition:
    any of them
}