rule TTP_XOR_WriteProcessMemory_0278 {
  strings:
    $key_0278 = { 55 0a [2] 67 28 [2] 61 1d [2] 4f 1d [2] 70 01 }

  condition:
    any of them
}