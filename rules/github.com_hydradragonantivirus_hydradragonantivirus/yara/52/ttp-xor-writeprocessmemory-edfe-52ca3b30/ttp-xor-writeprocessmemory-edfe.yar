rule TTP_XOR_WriteProcessMemory_edfe {
  strings:
    $key_edfe = { ba 8c [2] 88 ae [2] 8e 9b [2] a0 9b [2] 9f 87 }

  condition:
    any of them
}