rule TTP_XOR_WriteProcessMemory_3fd8 {
  strings:
    $key_3fd8 = { 68 aa [2] 5a 88 [2] 5c bd [2] 72 bd [2] 4d a1 }

  condition:
    any of them
}