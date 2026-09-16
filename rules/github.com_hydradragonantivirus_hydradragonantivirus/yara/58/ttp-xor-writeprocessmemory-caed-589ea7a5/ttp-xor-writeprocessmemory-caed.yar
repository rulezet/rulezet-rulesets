rule TTP_XOR_WriteProcessMemory_caed {
  strings:
    $key_caed = { 9d 9f [2] af bd [2] a9 88 [2] 87 88 [2] b8 94 }

  condition:
    any of them
}