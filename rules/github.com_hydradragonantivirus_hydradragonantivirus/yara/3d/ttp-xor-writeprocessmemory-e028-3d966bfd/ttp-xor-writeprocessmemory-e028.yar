rule TTP_XOR_WriteProcessMemory_e028 {
  strings:
    $key_e028 = { b7 5a [2] 85 78 [2] 83 4d [2] ad 4d [2] 92 51 }

  condition:
    any of them
}