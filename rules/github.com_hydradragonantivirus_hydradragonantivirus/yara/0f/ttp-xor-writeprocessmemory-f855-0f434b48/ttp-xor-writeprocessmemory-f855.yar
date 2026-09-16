rule TTP_XOR_WriteProcessMemory_f855 {
  strings:
    $key_f855 = { af 27 [2] 9d 05 [2] 9b 30 [2] b5 30 [2] 8a 2c }

  condition:
    any of them
}