rule TTP_XOR_WriteProcessMemory_5278 {
  strings:
    $key_5278 = { 05 0a [2] 37 28 [2] 31 1d [2] 1f 1d [2] 20 01 }

  condition:
    any of them
}