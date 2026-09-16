rule TTP_XOR_WriteProcessMemory_0d0d {
  strings:
    $key_0d0d = { 5a 7f [2] 68 5d [2] 6e 68 [2] 40 68 [2] 7f 74 }

  condition:
    any of them
}