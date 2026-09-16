rule TTP_XOR_WriteProcessMemory_4bcc {
  strings:
    $key_4bcc = { 1c be [2] 2e 9c [2] 28 a9 [2] 06 a9 [2] 39 b5 }

  condition:
    any of them
}