rule TTP_XOR_WriteProcessMemory_da18 {
  strings:
    $key_da18 = { 8d 6a [2] bf 48 [2] b9 7d [2] 97 7d [2] a8 61 }

  condition:
    any of them
}