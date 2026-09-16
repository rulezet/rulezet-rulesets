rule TTP_XOR_WriteProcessMemory_fdcb {
  strings:
    $key_fdcb = { aa b9 [2] 98 9b [2] 9e ae [2] b0 ae [2] 8f b2 }

  condition:
    any of them
}