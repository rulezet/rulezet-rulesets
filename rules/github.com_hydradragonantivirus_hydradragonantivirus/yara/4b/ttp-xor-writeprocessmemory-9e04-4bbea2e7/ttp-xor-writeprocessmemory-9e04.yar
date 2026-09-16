rule TTP_XOR_WriteProcessMemory_9e04 {
  strings:
    $key_9e04 = { c9 76 [2] fb 54 [2] fd 61 [2] d3 61 [2] ec 7d }

  condition:
    any of them
}