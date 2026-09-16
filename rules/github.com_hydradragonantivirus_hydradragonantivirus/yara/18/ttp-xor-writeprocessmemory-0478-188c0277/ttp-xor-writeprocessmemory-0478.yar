rule TTP_XOR_WriteProcessMemory_0478 {
  strings:
    $key_0478 = { 53 0a [2] 61 28 [2] 67 1d [2] 49 1d [2] 76 01 }

  condition:
    any of them
}