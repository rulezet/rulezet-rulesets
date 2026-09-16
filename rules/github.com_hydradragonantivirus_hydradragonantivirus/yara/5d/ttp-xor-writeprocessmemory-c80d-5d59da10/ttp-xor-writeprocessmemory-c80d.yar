rule TTP_XOR_WriteProcessMemory_c80d {
  strings:
    $key_c80d = { 9f 7f [2] ad 5d [2] ab 68 [2] 85 68 [2] ba 74 }

  condition:
    any of them
}