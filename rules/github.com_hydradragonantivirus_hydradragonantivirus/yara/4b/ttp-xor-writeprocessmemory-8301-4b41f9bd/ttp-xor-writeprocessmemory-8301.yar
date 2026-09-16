rule TTP_XOR_WriteProcessMemory_8301 {
  strings:
    $key_8301 = { d4 73 [2] e6 51 [2] e0 64 [2] ce 64 [2] f1 78 }

  condition:
    any of them
}