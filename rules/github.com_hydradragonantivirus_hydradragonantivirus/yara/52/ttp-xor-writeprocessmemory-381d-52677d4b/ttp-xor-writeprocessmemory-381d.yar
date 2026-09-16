rule TTP_XOR_WriteProcessMemory_381d {
  strings:
    $key_381d = { 6f 6f [2] 5d 4d [2] 5b 78 [2] 75 78 [2] 4a 64 }

  condition:
    any of them
}