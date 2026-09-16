rule TTP_XOR_WriteProcessMemory_fdc6 {
  strings:
    $key_fdc6 = { aa b4 [2] 98 96 [2] 9e a3 [2] b0 a3 [2] 8f bf }

  condition:
    any of them
}