rule TTP_XOR_WriteProcessMemory_1dba {
  strings:
    $key_1dba = { 4a c8 [2] 78 ea [2] 7e df [2] 50 df [2] 6f c3 }

  condition:
    any of them
}