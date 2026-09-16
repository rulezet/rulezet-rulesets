rule TTP_XOR_WriteProcessMemory_e78e {
  strings:
    $key_e78e = { b0 fc [2] 82 de [2] 84 eb [2] aa eb [2] 95 f7 }

  condition:
    any of them
}