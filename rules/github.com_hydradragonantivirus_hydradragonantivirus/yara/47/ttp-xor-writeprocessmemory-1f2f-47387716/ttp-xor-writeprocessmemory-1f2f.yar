rule TTP_XOR_WriteProcessMemory_1f2f {
  strings:
    $key_1f2f = { 48 5d [2] 7a 7f [2] 7c 4a [2] 52 4a [2] 6d 56 }

  condition:
    any of them
}