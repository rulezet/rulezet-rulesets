rule TTP_XOR_WriteProcessMemory_daff {
  strings:
    $key_daff = { 8d 8d [2] bf af [2] b9 9a [2] 97 9a [2] a8 86 }

  condition:
    any of them
}