rule TTP_XOR_WriteProcessMemory_af03 {
  strings:
    $key_af03 = { f8 71 [2] ca 53 [2] cc 66 [2] e2 66 [2] dd 7a }

  condition:
    any of them
}