rule TTP_XOR_WriteProcessMemory_efd8 {
  strings:
    $key_efd8 = { b8 aa [2] 8a 88 [2] 8c bd [2] a2 bd [2] 9d a1 }

  condition:
    any of them
}