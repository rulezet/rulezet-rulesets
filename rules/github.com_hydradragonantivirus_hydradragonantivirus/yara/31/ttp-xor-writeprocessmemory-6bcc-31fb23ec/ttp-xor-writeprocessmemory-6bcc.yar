rule TTP_XOR_WriteProcessMemory_6bcc {
  strings:
    $key_6bcc = { 3c be [2] 0e 9c [2] 08 a9 [2] 26 a9 [2] 19 b5 }

  condition:
    any of them
}