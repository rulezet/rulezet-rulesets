rule TTP_XOR_WriteProcessMemory_9f99 {
  strings:
    $key_9f99 = { c8 eb [2] fa c9 [2] fc fc [2] d2 fc [2] ed e0 }

  condition:
    any of them
}