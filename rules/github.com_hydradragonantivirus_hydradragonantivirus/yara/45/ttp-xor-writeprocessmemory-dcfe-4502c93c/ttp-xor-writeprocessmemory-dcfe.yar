rule TTP_XOR_WriteProcessMemory_dcfe {
  strings:
    $key_dcfe = { 8b 8c [2] b9 ae [2] bf 9b [2] 91 9b [2] ae 87 }

  condition:
    any of them
}