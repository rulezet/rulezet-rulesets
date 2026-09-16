rule TTP_XOR_WriteProcessMemory_cc99 {
  strings:
    $key_cc99 = { 9b eb [2] a9 c9 [2] af fc [2] 81 fc [2] be e0 }

  condition:
    any of them
}