rule TTP_XOR_WriteProcessMemory_bddd {
  strings:
    $key_bddd = { ea af [2] d8 8d [2] de b8 [2] f0 b8 [2] cf a4 }

  condition:
    any of them
}