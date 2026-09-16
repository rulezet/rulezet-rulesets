rule TTP_XOR_WriteProcessMemory_0d1f {
  strings:
    $key_0d1f = { 5a 6d [2] 68 4f [2] 6e 7a [2] 40 7a [2] 7f 66 }

  condition:
    any of them
}