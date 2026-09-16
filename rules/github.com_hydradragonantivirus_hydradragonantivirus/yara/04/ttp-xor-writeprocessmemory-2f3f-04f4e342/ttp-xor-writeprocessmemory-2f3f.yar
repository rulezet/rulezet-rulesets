rule TTP_XOR_WriteProcessMemory_2f3f {
  strings:
    $key_2f3f = { 78 4d [2] 4a 6f [2] 4c 5a [2] 62 5a [2] 5d 46 }

  condition:
    any of them
}