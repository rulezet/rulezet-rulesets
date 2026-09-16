rule TTP_XOR_WriteProcessMemory_0448 {
  strings:
    $key_0448 = { 53 3a [2] 61 18 [2] 67 2d [2] 49 2d [2] 76 31 }

  condition:
    any of them
}