rule TTP_XOR_WriteProcessMemory_fb8d {
  strings:
    $key_fb8d = { ac ff [2] 9e dd [2] 98 e8 [2] b6 e8 [2] 89 f4 }

  condition:
    any of them
}