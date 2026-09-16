rule TTP_XOR_WriteProcessMemory_b301 {
  strings:
    $key_b301 = { e4 73 [2] d6 51 [2] d0 64 [2] fe 64 [2] c1 78 }

  condition:
    any of them
}