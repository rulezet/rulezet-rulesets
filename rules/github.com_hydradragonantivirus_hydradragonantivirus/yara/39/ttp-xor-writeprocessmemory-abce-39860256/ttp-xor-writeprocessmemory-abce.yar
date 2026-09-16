rule TTP_XOR_WriteProcessMemory_abce {
  strings:
    $key_abce = { fc bc [2] ce 9e [2] c8 ab [2] e6 ab [2] d9 b7 }

  condition:
    any of them
}