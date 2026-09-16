rule TTP_XOR_WriteProcessMemory_f896 {
  strings:
    $key_f896 = { af e4 [2] 9d c6 [2] 9b f3 [2] b5 f3 [2] 8a ef }

  condition:
    any of them
}