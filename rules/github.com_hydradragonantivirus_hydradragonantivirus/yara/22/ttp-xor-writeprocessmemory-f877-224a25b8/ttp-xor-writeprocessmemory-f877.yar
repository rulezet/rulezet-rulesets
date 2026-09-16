rule TTP_XOR_WriteProcessMemory_f877 {
  strings:
    $key_f877 = { af 05 [2] 9d 27 [2] 9b 12 [2] b5 12 [2] 8a 0e }

  condition:
    any of them
}