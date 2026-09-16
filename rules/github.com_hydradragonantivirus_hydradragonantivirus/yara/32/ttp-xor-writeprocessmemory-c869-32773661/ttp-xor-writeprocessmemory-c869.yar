rule TTP_XOR_WriteProcessMemory_c869 {
  strings:
    $key_c869 = { 9f 1b [2] ad 39 [2] ab 0c [2] 85 0c [2] ba 10 }

  condition:
    any of them
}