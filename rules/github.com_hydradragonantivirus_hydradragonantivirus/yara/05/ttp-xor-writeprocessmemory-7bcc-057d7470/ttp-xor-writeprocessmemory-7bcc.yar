rule TTP_XOR_WriteProcessMemory_7bcc {
  strings:
    $key_7bcc = { 2c be [2] 1e 9c [2] 18 a9 [2] 36 a9 [2] 09 b5 }

  condition:
    any of them
}