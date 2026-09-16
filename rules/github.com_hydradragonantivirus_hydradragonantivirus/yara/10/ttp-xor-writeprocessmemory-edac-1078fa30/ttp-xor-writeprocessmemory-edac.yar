rule TTP_XOR_WriteProcessMemory_edac {
  strings:
    $key_edac = { ba de [2] 88 fc [2] 8e c9 [2] a0 c9 [2] 9f d5 }

  condition:
    any of them
}