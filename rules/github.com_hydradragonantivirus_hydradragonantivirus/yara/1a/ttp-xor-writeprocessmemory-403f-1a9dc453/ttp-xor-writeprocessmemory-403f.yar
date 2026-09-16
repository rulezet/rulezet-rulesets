rule TTP_XOR_WriteProcessMemory_403f {
  strings:
    $key_403f = { 17 4d [2] 25 6f [2] 23 5a [2] 0d 5a [2] 32 46 }

  condition:
    any of them
}