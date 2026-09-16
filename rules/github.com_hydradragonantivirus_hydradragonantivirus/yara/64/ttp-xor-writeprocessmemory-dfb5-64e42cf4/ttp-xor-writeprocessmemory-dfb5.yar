rule TTP_XOR_WriteProcessMemory_dfb5 {
  strings:
    $key_dfb5 = { 88 c7 [2] ba e5 [2] bc d0 [2] 92 d0 [2] ad cc }

  condition:
    any of them
}