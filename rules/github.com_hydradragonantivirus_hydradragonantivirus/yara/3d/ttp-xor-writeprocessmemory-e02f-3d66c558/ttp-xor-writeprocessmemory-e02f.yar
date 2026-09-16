rule TTP_XOR_WriteProcessMemory_e02f {
  strings:
    $key_e02f = { b7 5d [2] 85 7f [2] 83 4a [2] ad 4a [2] 92 56 }

  condition:
    any of them
}