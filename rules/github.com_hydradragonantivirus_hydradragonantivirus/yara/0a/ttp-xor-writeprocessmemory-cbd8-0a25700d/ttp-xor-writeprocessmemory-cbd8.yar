rule TTP_XOR_WriteProcessMemory_cbd8 {
  strings:
    $key_cbd8 = { 9c aa [2] ae 88 [2] a8 bd [2] 86 bd [2] b9 a1 }

  condition:
    any of them
}