rule TTP_XOR_WriteProcessMemory_dc01 {
  strings:
    $key_dc01 = { 8b 73 [2] b9 51 [2] bf 64 [2] 91 64 [2] ae 78 }

  condition:
    any of them
}