rule TTP_XOR_WriteProcessMemory_ffff {
  strings:
    $key_ffff = { a8 8d [2] 9a af [2] 9c 9a [2] b2 9a [2] 8d 86 }

  condition:
    any of them
}