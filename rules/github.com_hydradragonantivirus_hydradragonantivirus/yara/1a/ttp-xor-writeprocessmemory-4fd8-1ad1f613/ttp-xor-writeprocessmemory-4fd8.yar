rule TTP_XOR_WriteProcessMemory_4fd8 {
  strings:
    $key_4fd8 = { 18 aa [2] 2a 88 [2] 2c bd [2] 02 bd [2] 3d a1 }

  condition:
    any of them
}