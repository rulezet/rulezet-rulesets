rule TTP_XOR_WriteProcessMemory_f9d9 {
  strings:
    $key_f9d9 = { ae ab [2] 9c 89 [2] 9a bc [2] b4 bc [2] 8b a0 }

  condition:
    any of them
}