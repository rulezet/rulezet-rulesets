rule TTP_XOR_WriteProcessMemory_cd99 {
  strings:
    $key_cd99 = { 9a eb [2] a8 c9 [2] ae fc [2] 80 fc [2] bf e0 }

  condition:
    any of them
}