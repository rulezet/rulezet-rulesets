rule TTP_XOR_WriteProcessMemory_dcf4 {
  strings:
    $key_dcf4 = { 8b 86 [2] b9 a4 [2] bf 91 [2] 91 91 [2] ae 8d }

  condition:
    any of them
}