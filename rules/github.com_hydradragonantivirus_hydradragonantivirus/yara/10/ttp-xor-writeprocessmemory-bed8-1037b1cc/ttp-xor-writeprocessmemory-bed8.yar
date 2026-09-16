rule TTP_XOR_WriteProcessMemory_bed8 {
  strings:
    $key_bed8 = { e9 aa [2] db 88 [2] dd bd [2] f3 bd [2] cc a1 }

  condition:
    any of them
}