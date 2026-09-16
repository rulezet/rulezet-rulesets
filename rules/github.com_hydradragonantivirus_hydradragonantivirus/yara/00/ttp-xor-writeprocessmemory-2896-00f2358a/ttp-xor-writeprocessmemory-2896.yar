rule TTP_XOR_WriteProcessMemory_2896 {
  strings:
    $key_2896 = { 7f e4 [2] 4d c6 [2] 4b f3 [2] 65 f3 [2] 5a ef }

  condition:
    any of them
}