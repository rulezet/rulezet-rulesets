rule TTP_XOR_WriteProcessMemory_6bba {
  strings:
    $key_6bba = { 3c c8 [2] 0e ea [2] 08 df [2] 26 df [2] 19 c3 }

  condition:
    any of them
}