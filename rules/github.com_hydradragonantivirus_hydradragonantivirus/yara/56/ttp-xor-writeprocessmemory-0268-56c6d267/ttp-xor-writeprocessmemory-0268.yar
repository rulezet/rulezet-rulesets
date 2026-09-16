rule TTP_XOR_WriteProcessMemory_0268 {
  strings:
    $key_0268 = { 55 1a [2] 67 38 [2] 61 0d [2] 4f 0d [2] 70 11 }

  condition:
    any of them
}