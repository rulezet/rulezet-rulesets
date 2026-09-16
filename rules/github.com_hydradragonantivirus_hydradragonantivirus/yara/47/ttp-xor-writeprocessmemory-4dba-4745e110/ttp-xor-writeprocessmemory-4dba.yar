rule TTP_XOR_WriteProcessMemory_4dba {
  strings:
    $key_4dba = { 1a c8 [2] 28 ea [2] 2e df [2] 00 df [2] 3f c3 }

  condition:
    any of them
}