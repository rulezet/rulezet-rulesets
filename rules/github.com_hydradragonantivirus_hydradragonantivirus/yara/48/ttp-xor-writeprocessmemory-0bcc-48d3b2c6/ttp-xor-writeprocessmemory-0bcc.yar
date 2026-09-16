rule TTP_XOR_WriteProcessMemory_0bcc {
  strings:
    $key_0bcc = { 5c be [2] 6e 9c [2] 68 a9 [2] 46 a9 [2] 79 b5 }

  condition:
    any of them
}