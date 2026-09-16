rule TTP_XOR_WriteProcessMemory_86dc {
  strings:
    $key_86dc = { d1 ae [2] e3 8c [2] e5 b9 [2] cb b9 [2] f4 a5 }

  condition:
    any of them
}