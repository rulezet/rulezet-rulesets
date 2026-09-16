rule TTP_XOR_WriteProcessMemory_dbad {
  strings:
    $key_dbad = { 8c df [2] be fd [2] b8 c8 [2] 96 c8 [2] a9 d4 }

  condition:
    any of them
}