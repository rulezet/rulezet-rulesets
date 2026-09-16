rule TTP_XOR_WriteProcessMemory_0d1d {
  strings:
    $key_0d1d = { 5a 6f [2] 68 4d [2] 6e 78 [2] 40 78 [2] 7f 64 }

  condition:
    any of them
}