rule TTP_XOR_WriteProcessMemory_4118 {
  strings:
    $key_4118 = { 16 6a [2] 24 48 [2] 22 7d [2] 0c 7d [2] 33 61 }

  condition:
    any of them
}