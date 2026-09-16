rule TTP_XOR_WriteProcessMemory_e00d {
  strings:
    $key_e00d = { b7 7f [2] 85 5d [2] 83 68 [2] ad 68 [2] 92 74 }

  condition:
    any of them
}