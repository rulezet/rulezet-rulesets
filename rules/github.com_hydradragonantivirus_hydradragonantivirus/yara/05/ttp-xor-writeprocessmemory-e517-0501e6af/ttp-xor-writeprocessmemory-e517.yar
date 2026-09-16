rule TTP_XOR_WriteProcessMemory_e517 {
  strings:
    $key_e517 = { b2 65 [2] 80 47 [2] 86 72 [2] a8 72 [2] 97 6e }

  condition:
    any of them
}