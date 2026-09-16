rule TTP_XOR_WriteProcessMemory_ab99 {
  strings:
    $key_ab99 = { fc eb [2] ce c9 [2] c8 fc [2] e6 fc [2] d9 e0 }

  condition:
    any of them
}