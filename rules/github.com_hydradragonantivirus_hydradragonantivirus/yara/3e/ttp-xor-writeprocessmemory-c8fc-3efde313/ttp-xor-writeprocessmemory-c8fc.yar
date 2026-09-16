rule TTP_XOR_WriteProcessMemory_c8fc {
  strings:
    $key_c8fc = { 9f 8e [2] ad ac [2] ab 99 [2] 85 99 [2] ba 85 }

  condition:
    any of them
}