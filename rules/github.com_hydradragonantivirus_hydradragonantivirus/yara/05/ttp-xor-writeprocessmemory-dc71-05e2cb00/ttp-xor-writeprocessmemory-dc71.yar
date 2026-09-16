rule TTP_XOR_WriteProcessMemory_dc71 {
  strings:
    $key_dc71 = { 8b 03 [2] b9 21 [2] bf 14 [2] 91 14 [2] ae 08 }

  condition:
    any of them
}