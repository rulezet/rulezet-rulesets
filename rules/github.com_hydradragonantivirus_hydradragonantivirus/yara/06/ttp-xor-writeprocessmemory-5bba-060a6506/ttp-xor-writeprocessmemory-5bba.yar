rule TTP_XOR_WriteProcessMemory_5bba {
  strings:
    $key_5bba = { 0c c8 [2] 3e ea [2] 38 df [2] 16 df [2] 29 c3 }

  condition:
    any of them
}