rule TTP_XOR_WriteProcessMemory_11d8 {
  strings:
    $key_11d8 = { 46 aa [2] 74 88 [2] 72 bd [2] 5c bd [2] 63 a1 }

  condition:
    any of them
}