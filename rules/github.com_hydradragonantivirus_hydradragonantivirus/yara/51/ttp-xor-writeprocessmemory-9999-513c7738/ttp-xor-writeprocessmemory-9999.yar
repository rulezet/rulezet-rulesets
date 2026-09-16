rule TTP_XOR_WriteProcessMemory_9999 {
  strings:
    $key_9999 = { ce eb [2] fc c9 [2] fa fc [2] d4 fc [2] eb e0 }

  condition:
    any of them
}