rule TTP_XOR_WriteProcessMemory_e394 {
  strings:
    $key_e394 = { b4 e6 [2] 86 c4 [2] 80 f1 [2] ae f1 [2] 91 ed }

  condition:
    any of them
}