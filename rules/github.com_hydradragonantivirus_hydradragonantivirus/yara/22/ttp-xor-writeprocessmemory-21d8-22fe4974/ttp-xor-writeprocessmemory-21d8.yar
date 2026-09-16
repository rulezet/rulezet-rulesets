rule TTP_XOR_WriteProcessMemory_21d8 {
  strings:
    $key_21d8 = { 76 aa [2] 44 88 [2] 42 bd [2] 6c bd [2] 53 a1 }

  condition:
    any of them
}