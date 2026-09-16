rule TTP_XOR_WriteProcessMemory_da28 {
  strings:
    $key_da28 = { 8d 5a [2] bf 78 [2] b9 4d [2] 97 4d [2] a8 51 }

  condition:
    any of them
}