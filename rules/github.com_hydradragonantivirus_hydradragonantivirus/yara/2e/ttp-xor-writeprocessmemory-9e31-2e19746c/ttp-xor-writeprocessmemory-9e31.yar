rule TTP_XOR_WriteProcessMemory_9e31 {
  strings:
    $key_9e31 = { c9 43 [2] fb 61 [2] fd 54 [2] d3 54 [2] ec 48 }

  condition:
    any of them
}