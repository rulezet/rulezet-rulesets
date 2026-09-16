rule TTP_XOR_WriteProcessMemory_36d8 {
  strings:
    $key_36d8 = { 61 aa [2] 53 88 [2] 55 bd [2] 7b bd [2] 44 a1 }

  condition:
    any of them
}