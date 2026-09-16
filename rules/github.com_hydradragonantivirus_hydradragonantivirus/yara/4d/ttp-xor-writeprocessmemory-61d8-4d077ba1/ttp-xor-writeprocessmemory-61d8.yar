rule TTP_XOR_WriteProcessMemory_61d8 {
  strings:
    $key_61d8 = { 36 aa [2] 04 88 [2] 02 bd [2] 2c bd [2] 13 a1 }

  condition:
    any of them
}