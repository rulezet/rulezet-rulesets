rule TTP_XOR_WriteProcessMemory_ab01 {
  strings:
    $key_ab01 = { fc 73 [2] ce 51 [2] c8 64 [2] e6 64 [2] d9 78 }

  condition:
    any of them
}