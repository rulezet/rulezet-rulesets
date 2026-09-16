rule TTP_XOR_WriteProcessMemory_16e8 {
  strings:
    $key_16e8 = { 41 9a [2] 73 b8 [2] 75 8d [2] 5b 8d [2] 64 91 }

  condition:
    any of them
}