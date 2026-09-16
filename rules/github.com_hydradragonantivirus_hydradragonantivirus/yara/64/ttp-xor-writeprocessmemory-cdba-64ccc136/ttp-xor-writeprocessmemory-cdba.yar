rule TTP_XOR_WriteProcessMemory_cdba {
  strings:
    $key_cdba = { 9a c8 [2] a8 ea [2] ae df [2] 80 df [2] bf c3 }

  condition:
    any of them
}