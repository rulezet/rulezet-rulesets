rule TTP_XOR_WriteProcessMemory_ee8e {
  strings:
    $key_ee8e = { b9 fc [2] 8b de [2] 8d eb [2] a3 eb [2] 9c f7 }

  condition:
    any of them
}