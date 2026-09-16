rule TTP_XOR_WriteProcessMemory_eacb {
  strings:
    $key_eacb = { bd b9 [2] 8f 9b [2] 89 ae [2] a7 ae [2] 98 b2 }

  condition:
    any of them
}