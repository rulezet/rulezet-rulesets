rule TTP_XOR_WriteProcessMemory_7ed8 {
  strings:
    $key_7ed8 = { 29 aa [2] 1b 88 [2] 1d bd [2] 33 bd [2] 0c a1 }

  condition:
    any of them
}