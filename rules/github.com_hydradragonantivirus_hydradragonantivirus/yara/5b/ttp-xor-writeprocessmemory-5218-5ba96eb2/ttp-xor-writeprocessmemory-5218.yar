rule TTP_XOR_WriteProcessMemory_5218 {
  strings:
    $key_5218 = { 05 6a [2] 37 48 [2] 31 7d [2] 1f 7d [2] 20 61 }

  condition:
    any of them
}