rule TTP_XOR_WriteProcessMemory_3893 {
  strings:
    $key_3893 = { 6f e1 [2] 5d c3 [2] 5b f6 [2] 75 f6 [2] 4a ea }

  condition:
    any of them
}