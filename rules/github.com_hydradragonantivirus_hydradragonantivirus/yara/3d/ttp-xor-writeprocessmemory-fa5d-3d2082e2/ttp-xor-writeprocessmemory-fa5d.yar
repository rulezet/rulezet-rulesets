rule TTP_XOR_WriteProcessMemory_fa5d {
  strings:
    $key_fa5d = { ad 2f [2] 9f 0d [2] 99 38 [2] b7 38 [2] 88 24 }

  condition:
    any of them
}