rule TTP_XOR_WriteProcessMemory_2bba {
  strings:
    $key_2bba = { 7c c8 [2] 4e ea [2] 48 df [2] 66 df [2] 59 c3 }

  condition:
    any of them
}