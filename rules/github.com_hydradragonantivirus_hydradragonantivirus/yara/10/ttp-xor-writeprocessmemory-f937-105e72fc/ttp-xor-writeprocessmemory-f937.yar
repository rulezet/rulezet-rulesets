rule TTP_XOR_WriteProcessMemory_f937 {
  strings:
    $key_f937 = { ae 45 [2] 9c 67 [2] 9a 52 [2] b4 52 [2] 8b 4e }

  condition:
    any of them
}