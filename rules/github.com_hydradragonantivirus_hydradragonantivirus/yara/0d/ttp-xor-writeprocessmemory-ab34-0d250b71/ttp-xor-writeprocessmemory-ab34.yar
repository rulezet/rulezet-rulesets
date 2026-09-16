rule TTP_XOR_WriteProcessMemory_ab34 {
  strings:
    $key_ab34 = { fc 46 [2] ce 64 [2] c8 51 [2] e6 51 [2] d9 4d }

  condition:
    any of them
}