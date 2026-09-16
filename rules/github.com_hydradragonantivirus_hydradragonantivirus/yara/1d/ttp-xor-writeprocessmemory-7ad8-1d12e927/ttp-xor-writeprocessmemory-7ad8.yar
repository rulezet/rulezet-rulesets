rule TTP_XOR_WriteProcessMemory_7ad8 {
  strings:
    $key_7ad8 = { 2d aa [2] 1f 88 [2] 19 bd [2] 37 bd [2] 08 a1 }

  condition:
    any of them
}