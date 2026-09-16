rule TTP_XOR_WriteProcessMemory_c852 {
  strings:
    $key_c852 = { 9f 20 [2] ad 02 [2] ab 37 [2] 85 37 [2] ba 2b }

  condition:
    any of them
}