rule TTP_XOR_WriteProcessMemory_4168 {
  strings:
    $key_4168 = { 16 1a [2] 24 38 [2] 22 0d [2] 0c 0d [2] 33 11 }

  condition:
    any of them
}