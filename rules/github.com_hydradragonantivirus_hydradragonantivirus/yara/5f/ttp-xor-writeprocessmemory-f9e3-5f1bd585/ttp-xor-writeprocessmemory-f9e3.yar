rule TTP_XOR_WriteProcessMemory_f9e3 {
  strings:
    $key_f9e3 = { ae 91 [2] 9c b3 [2] 9a 86 [2] b4 86 [2] 8b 9a }

  condition:
    any of them
}