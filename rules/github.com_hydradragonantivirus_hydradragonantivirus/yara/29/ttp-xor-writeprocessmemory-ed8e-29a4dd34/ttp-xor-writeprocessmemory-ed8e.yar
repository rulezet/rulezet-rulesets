rule TTP_XOR_WriteProcessMemory_ed8e {
  strings:
    $key_ed8e = { ba fc [2] 88 de [2] 8e eb [2] a0 eb [2] 9f f7 }

  condition:
    any of them
}