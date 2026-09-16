rule TTP_XOR_WriteProcessMemory_dcba {
  strings:
    $key_dcba = { 8b c8 [2] b9 ea [2] bf df [2] 91 df [2] ae c3 }

  condition:
    any of them
}