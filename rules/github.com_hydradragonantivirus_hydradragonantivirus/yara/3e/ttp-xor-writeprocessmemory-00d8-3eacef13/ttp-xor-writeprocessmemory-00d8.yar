rule TTP_XOR_WriteProcessMemory_00d8 {
  strings:
    $key_00d8 = { 57 aa [2] 65 88 [2] 63 bd [2] 4d bd [2] 72 a1 }

  condition:
    any of them
}