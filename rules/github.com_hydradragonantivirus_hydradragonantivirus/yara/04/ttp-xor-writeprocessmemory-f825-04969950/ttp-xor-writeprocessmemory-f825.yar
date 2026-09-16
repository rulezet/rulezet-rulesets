rule TTP_XOR_WriteProcessMemory_f825 {
  strings:
    $key_f825 = { af 57 [2] 9d 75 [2] 9b 40 [2] b5 40 [2] 8a 5c }

  condition:
    any of them
}