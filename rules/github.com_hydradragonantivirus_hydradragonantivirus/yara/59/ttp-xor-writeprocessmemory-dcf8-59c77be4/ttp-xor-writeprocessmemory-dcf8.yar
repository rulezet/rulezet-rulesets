rule TTP_XOR_WriteProcessMemory_dcf8 {
  strings:
    $key_dcf8 = { 8b 8a [2] b9 a8 [2] bf 9d [2] 91 9d [2] ae 81 }

  condition:
    any of them
}