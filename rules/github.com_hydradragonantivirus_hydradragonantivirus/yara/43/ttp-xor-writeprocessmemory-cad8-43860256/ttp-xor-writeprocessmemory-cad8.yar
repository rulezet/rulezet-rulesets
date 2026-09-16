rule TTP_XOR_WriteProcessMemory_cad8 {
  strings:
    $key_cad8 = { 9d aa [2] af 88 [2] a9 bd [2] 87 bd [2] b8 a1 }

  condition:
    any of them
}