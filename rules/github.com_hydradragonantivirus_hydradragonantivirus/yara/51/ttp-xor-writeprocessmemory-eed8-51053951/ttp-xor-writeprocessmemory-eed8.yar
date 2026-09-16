rule TTP_XOR_WriteProcessMemory_eed8 {
  strings:
    $key_eed8 = { b9 aa [2] 8b 88 [2] 8d bd [2] a3 bd [2] 9c a1 }

  condition:
    any of them
}