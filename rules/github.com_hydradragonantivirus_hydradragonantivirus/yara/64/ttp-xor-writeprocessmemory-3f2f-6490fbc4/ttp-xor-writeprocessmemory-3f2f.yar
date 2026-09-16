rule TTP_XOR_WriteProcessMemory_3f2f {
  strings:
    $key_3f2f = { 68 5d [2] 5a 7f [2] 5c 4a [2] 72 4a [2] 4d 56 }

  condition:
    any of them
}