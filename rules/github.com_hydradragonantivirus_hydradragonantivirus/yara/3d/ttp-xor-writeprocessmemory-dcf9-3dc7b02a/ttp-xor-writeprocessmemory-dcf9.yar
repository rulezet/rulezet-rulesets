rule TTP_XOR_WriteProcessMemory_dcf9 {
  strings:
    $key_dcf9 = { 8b 8b [2] b9 a9 [2] bf 9c [2] 91 9c [2] ae 80 }

  condition:
    any of them
}