rule TTP_XOR_WriteProcessMemory_dcee {
  strings:
    $key_dcee = { 8b 9c [2] b9 be [2] bf 8b [2] 91 8b [2] ae 97 }

  condition:
    any of them
}