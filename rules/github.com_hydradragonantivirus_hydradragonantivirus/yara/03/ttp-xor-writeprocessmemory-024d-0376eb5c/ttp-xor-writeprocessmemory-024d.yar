rule TTP_XOR_WriteProcessMemory_024d {
  strings:
    $key_024d = { 55 3f [2] 67 1d [2] 61 28 [2] 4f 28 [2] 70 34 }

  condition:
    any of them
}