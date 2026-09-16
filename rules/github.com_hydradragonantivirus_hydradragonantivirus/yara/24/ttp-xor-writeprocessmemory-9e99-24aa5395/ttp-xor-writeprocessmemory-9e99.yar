rule TTP_XOR_WriteProcessMemory_9e99 {
  strings:
    $key_9e99 = { c9 eb [2] fb c9 [2] fd fc [2] d3 fc [2] ec e0 }

  condition:
    any of them
}