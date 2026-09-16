rule TTP_XOR_WriteProcessMemory_dcfc {
  strings:
    $key_dcfc = { 8b 8e [2] b9 ac [2] bf 99 [2] 91 99 [2] ae 85 }

  condition:
    any of them
}