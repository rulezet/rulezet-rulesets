rule TTP_XOR_WriteProcessMemory_feea {
  strings:
    $key_feea = { a9 98 [2] 9b ba [2] 9d 8f [2] b3 8f [2] 8c 93 }

  condition:
    any of them
}