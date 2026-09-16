rule TTP_XOR_WriteProcessMemory_cd86 {
  strings:
    $key_cd86 = { 9a f4 [2] a8 d6 [2] ae e3 [2] 80 e3 [2] bf ff }

  condition:
    any of them
}