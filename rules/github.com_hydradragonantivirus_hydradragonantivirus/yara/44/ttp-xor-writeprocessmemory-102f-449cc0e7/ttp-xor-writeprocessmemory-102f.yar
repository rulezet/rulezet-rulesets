rule TTP_XOR_WriteProcessMemory_102f {
  strings:
    $key_102f = { 47 5d [2] 75 7f [2] 73 4a [2] 5d 4a [2] 62 56 }

  condition:
    any of them
}