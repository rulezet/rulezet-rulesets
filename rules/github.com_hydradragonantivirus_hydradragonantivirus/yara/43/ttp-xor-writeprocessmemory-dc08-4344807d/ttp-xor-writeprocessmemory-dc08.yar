rule TTP_XOR_WriteProcessMemory_dc08 {
  strings:
    $key_dc08 = { 8b 7a [2] b9 58 [2] bf 6d [2] 91 6d [2] ae 71 }

  condition:
    any of them
}