rule TTP_XOR_WriteProcessMemory_7686 {
  strings:
    $key_7686 = { 21 f4 [2] 13 d6 [2] 15 e3 [2] 3b e3 [2] 04 ff }

  condition:
    any of them
}