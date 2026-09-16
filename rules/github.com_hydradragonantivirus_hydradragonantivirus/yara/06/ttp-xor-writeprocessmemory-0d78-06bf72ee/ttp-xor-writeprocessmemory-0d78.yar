rule TTP_XOR_WriteProcessMemory_0d78 {
  strings:
    $key_0d78 = { 5a 0a [2] 68 28 [2] 6e 1d [2] 40 1d [2] 7f 01 }

  condition:
    any of them
}