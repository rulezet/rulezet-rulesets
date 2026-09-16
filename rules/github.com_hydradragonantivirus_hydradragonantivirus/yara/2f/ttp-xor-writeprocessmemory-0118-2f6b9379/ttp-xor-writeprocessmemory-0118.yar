rule TTP_XOR_WriteProcessMemory_0118 {
  strings:
    $key_0118 = { 56 6a [2] 64 48 [2] 62 7d [2] 4c 7d [2] 73 61 }

  condition:
    any of them
}