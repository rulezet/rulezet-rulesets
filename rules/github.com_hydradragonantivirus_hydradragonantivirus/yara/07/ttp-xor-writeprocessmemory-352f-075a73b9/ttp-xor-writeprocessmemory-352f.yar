rule TTP_XOR_WriteProcessMemory_352f {
  strings:
    $key_352f = { 62 5d [2] 50 7f [2] 56 4a [2] 78 4a [2] 47 56 }

  condition:
    any of them
}