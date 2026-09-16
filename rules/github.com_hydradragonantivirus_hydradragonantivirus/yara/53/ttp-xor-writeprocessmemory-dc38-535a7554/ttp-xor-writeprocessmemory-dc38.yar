rule TTP_XOR_WriteProcessMemory_dc38 {
  strings:
    $key_dc38 = { 8b 4a [2] b9 68 [2] bf 5d [2] 91 5d [2] ae 41 }

  condition:
    any of them
}