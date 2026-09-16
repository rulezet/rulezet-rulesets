rule TTP_XOR_WriteProcessMemory_f993 {
  strings:
    $key_f993 = { ae e1 [2] 9c c3 [2] 9a f6 [2] b4 f6 [2] 8b ea }

  condition:
    any of them
}