rule TTP_XOR_WriteProcessMemory_06d8 {
  strings:
    $key_06d8 = { 51 aa [2] 63 88 [2] 65 bd [2] 4b bd [2] 74 a1 }

  condition:
    any of them
}