rule TTP_XOR_WriteProcessMemory_ab14 {
  strings:
    $key_ab14 = { fc 66 [2] ce 44 [2] c8 71 [2] e6 71 [2] d9 6d }

  condition:
    any of them
}