rule TTP_XOR_WriteProcessMemory_dbd8 {
  strings:
    $key_dbd8 = { 8c aa [2] be 88 [2] b8 bd [2] 96 bd [2] a9 a1 }

  condition:
    any of them
}