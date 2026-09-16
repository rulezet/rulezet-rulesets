rule TTP_XOR_WriteProcessMemory_52d8 {
  strings:
    $key_52d8 = { 05 aa [2] 37 88 [2] 31 bd [2] 1f bd [2] 20 a1 }

  condition:
    any of them
}