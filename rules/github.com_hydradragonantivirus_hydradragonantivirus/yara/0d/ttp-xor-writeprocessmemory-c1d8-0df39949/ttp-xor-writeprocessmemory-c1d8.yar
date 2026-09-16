rule TTP_XOR_WriteProcessMemory_c1d8 {
  strings:
    $key_c1d8 = { 96 aa [2] a4 88 [2] a2 bd [2] 8c bd [2] b3 a1 }

  condition:
    any of them
}