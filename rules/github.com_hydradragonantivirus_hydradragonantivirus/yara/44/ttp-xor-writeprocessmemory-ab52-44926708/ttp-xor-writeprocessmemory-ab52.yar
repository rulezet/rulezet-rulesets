rule TTP_XOR_WriteProcessMemory_ab52 {
  strings:
    $key_ab52 = { fc 20 [2] ce 02 [2] c8 37 [2] e6 37 [2] d9 2b }

  condition:
    any of them
}