rule TTP_XOR_WriteProcessMemory_dccb {
  strings:
    $key_dccb = { 8b b9 [2] b9 9b [2] bf ae [2] 91 ae [2] ae b2 }

  condition:
    any of them
}