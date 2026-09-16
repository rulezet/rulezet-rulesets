rule TTP_XOR_WriteProcessMemory_bda9 {
  strings:
    $key_bda9 = { ea db [2] d8 f9 [2] de cc [2] f0 cc [2] cf d0 }

  condition:
    any of them
}