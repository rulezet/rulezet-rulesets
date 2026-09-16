rule TTP_XOR_WriteProcessMemory_385f {
  strings:
    $key_385f = { 6f 2d [2] 5d 0f [2] 5b 3a [2] 75 3a [2] 4a 26 }

  condition:
    any of them
}