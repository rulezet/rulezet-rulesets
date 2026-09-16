rule TTP_XOR_WriteProcessMemory_f9dc {
  strings:
    $key_f9dc = { ae ae [2] 9c 8c [2] 9a b9 [2] b4 b9 [2] 8b a5 }

  condition:
    any of them
}