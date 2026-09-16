rule TTP_XOR_WriteProcessMemory_fa1d {
  strings:
    $key_fa1d = { ad 6f [2] 9f 4d [2] 99 78 [2] b7 78 [2] 88 64 }

  condition:
    any of them
}