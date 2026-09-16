rule TTP_XOR_WriteProcessMemory_dfdd {
  strings:
    $key_dfdd = { 88 af [2] ba 8d [2] bc b8 [2] 92 b8 [2] ad a4 }

  condition:
    any of them
}