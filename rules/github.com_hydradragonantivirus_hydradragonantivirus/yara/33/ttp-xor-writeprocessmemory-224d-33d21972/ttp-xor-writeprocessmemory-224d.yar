rule TTP_XOR_WriteProcessMemory_224d {
  strings:
    $key_224d = { 75 3f [2] 47 1d [2] 41 28 [2] 6f 28 [2] 50 34 }

  condition:
    any of them
}