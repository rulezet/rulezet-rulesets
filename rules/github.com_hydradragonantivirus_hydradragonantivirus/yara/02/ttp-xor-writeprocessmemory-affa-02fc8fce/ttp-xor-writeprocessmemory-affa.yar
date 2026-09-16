rule TTP_XOR_WriteProcessMemory_affa {
  strings:
    $key_affa = { f8 88 [2] ca aa [2] cc 9f [2] e2 9f [2] dd 83 }

  condition:
    any of them
}