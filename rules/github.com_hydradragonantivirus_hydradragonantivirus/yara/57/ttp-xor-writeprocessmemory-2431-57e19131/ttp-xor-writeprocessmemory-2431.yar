rule TTP_XOR_WriteProcessMemory_2431 {
  strings:
    $key_2431 = { 73 43 [2] 41 61 [2] 47 54 [2] 69 54 [2] 56 48 }

  condition:
    any of them
}