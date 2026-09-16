rule TTP_XOR_WriteProcessMemory_00fe {
  strings:
    $key_00fe = { 57 8c [2] 65 ae [2] 63 9b [2] 4d 9b [2] 72 87 }

  condition:
    any of them
}