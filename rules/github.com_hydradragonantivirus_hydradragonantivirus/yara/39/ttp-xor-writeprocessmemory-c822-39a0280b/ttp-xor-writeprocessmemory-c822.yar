rule TTP_XOR_WriteProcessMemory_c822 {
  strings:
    $key_c822 = { 9f 50 [2] ad 72 [2] ab 47 [2] 85 47 [2] ba 5b }

  condition:
    any of them
}