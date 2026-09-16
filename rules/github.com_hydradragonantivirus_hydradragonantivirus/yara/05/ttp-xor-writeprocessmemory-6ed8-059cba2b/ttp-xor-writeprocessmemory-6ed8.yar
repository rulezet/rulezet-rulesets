rule TTP_XOR_WriteProcessMemory_6ed8 {
  strings:
    $key_6ed8 = { 39 aa [2] 0b 88 [2] 0d bd [2] 23 bd [2] 1c a1 }

  condition:
    any of them
}