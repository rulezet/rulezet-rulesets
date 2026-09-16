rule TTP_XOR_WriteProcessMemory_2dba {
  strings:
    $key_2dba = { 7a c8 [2] 48 ea [2] 4e df [2] 60 df [2] 5f c3 }

  condition:
    any of them
}