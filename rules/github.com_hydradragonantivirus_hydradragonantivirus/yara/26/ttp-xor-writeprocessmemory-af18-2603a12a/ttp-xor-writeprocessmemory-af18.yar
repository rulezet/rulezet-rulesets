rule TTP_XOR_WriteProcessMemory_af18 {
  strings:
    $key_af18 = { f8 6a [2] ca 48 [2] cc 7d [2] e2 7d [2] dd 61 }

  condition:
    any of them
}