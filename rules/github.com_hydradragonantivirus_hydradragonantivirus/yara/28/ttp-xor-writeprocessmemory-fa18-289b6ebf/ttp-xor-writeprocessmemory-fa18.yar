rule TTP_XOR_WriteProcessMemory_fa18 {
  strings:
    $key_fa18 = { ad 6a [2] 9f 48 [2] 99 7d [2] b7 7d [2] 88 61 }

  condition:
    any of them
}