rule TTP_XOR_WriteProcessMemory_e907 {
  strings:
    $key_e907 = { be 75 [2] 8c 57 [2] 8a 62 [2] a4 62 [2] 9b 7e }

  condition:
    any of them
}