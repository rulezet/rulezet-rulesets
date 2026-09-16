rule TTP_XOR_WriteProcessMemory_bcd8 {
  strings:
    $key_bcd8 = { eb aa [2] d9 88 [2] df bd [2] f1 bd [2] ce a1 }

  condition:
    any of them
}