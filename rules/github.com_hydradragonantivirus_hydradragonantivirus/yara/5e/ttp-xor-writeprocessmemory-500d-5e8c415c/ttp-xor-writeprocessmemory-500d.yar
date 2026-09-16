rule TTP_XOR_WriteProcessMemory_500d {
  strings:
    $key_500d = { 07 7f [2] 35 5d [2] 33 68 [2] 1d 68 [2] 22 74 }

  condition:
    any of them
}