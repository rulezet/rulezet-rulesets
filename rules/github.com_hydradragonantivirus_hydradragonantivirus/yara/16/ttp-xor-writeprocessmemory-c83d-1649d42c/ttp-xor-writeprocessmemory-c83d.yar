rule TTP_XOR_WriteProcessMemory_c83d {
  strings:
    $key_c83d = { 9f 4f [2] ad 6d [2] ab 58 [2] 85 58 [2] ba 44 }

  condition:
    any of them
}