rule TTP_XOR_WriteProcessMemory_fa2d {
  strings:
    $key_fa2d = { ad 5f [2] 9f 7d [2] 99 48 [2] b7 48 [2] 88 54 }

  condition:
    any of them
}