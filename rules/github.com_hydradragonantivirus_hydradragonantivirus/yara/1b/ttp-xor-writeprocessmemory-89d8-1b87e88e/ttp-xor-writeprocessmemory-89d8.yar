rule TTP_XOR_WriteProcessMemory_89d8 {
  strings:
    $key_89d8 = { de aa [2] ec 88 [2] ea bd [2] c4 bd [2] fb a1 }

  condition:
    any of them
}