rule TTP_XOR_WriteProcessMemory_27fe {
  strings:
    $key_27fe = { 70 8c [2] 42 ae [2] 44 9b [2] 6a 9b [2] 55 87 }

  condition:
    any of them
}