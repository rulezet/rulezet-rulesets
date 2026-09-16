rule TTP_XOR_WriteProcessMemory_0cfe {
  strings:
    $key_0cfe = { 5b 8c [2] 69 ae [2] 6f 9b [2] 41 9b [2] 7e 87 }

  condition:
    any of them
}