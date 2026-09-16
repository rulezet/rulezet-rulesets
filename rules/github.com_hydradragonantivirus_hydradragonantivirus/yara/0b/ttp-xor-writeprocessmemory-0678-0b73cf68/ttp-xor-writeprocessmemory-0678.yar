rule TTP_XOR_WriteProcessMemory_0678 {
  strings:
    $key_0678 = { 51 0a [2] 63 28 [2] 65 1d [2] 4b 1d [2] 74 01 }

  condition:
    any of them
}