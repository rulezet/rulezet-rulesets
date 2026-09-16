rule TTP_XOR_WriteProcessMemory_acdb {
  strings:
    $key_acdb = { fb a9 [2] c9 8b [2] cf be [2] e1 be [2] de a2 }

  condition:
    any of them
}