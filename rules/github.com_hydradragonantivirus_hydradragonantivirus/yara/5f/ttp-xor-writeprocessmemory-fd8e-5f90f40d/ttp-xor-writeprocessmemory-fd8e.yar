rule TTP_XOR_WriteProcessMemory_fd8e {
  strings:
    $key_fd8e = { aa fc [2] 98 de [2] 9e eb [2] b0 eb [2] 8f f7 }

  condition:
    any of them
}