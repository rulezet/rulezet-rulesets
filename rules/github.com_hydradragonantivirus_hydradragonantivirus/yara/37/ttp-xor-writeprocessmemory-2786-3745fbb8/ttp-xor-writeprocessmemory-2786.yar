rule TTP_XOR_WriteProcessMemory_2786 {
  strings:
    $key_2786 = { 70 f4 [2] 42 d6 [2] 44 e3 [2] 6a e3 [2] 55 ff }

  condition:
    any of them
}