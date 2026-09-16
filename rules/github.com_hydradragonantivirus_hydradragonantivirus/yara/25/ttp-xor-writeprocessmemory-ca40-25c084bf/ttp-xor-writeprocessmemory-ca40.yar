rule TTP_XOR_WriteProcessMemory_ca40 {
  strings:
    $key_ca40 = { 9d 32 [2] af 10 [2] a9 25 [2] 87 25 [2] b8 39 }

  condition:
    any of them
}