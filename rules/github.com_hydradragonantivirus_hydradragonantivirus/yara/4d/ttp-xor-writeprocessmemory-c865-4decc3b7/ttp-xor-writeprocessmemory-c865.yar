rule TTP_XOR_WriteProcessMemory_c865 {
  strings:
    $key_c865 = { 9f 17 [2] ad 35 [2] ab 00 [2] 85 00 [2] ba 1c }

  condition:
    any of them
}