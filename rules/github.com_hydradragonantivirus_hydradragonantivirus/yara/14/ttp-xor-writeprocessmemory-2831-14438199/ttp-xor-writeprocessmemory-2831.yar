rule TTP_XOR_WriteProcessMemory_2831 {
  strings:
    $key_2831 = { 7f 43 [2] 4d 61 [2] 4b 54 [2] 65 54 [2] 5a 48 }

  condition:
    any of them
}