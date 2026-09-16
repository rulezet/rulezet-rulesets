rule TTP_XOR_WriteProcessMemory_c805 {
  strings:
    $key_c805 = { 9f 77 [2] ad 55 [2] ab 60 [2] 85 60 [2] ba 7c }

  condition:
    any of them
}