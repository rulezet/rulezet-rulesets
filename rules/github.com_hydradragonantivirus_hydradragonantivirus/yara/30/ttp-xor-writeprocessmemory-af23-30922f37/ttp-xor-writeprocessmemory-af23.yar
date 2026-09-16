rule TTP_XOR_WriteProcessMemory_af23 {
  strings:
    $key_af23 = { f8 51 [2] ca 73 [2] cc 46 [2] e2 46 [2] dd 5a }

  condition:
    any of them
}