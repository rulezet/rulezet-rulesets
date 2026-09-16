rule TTP_XOR_WriteProcessMemory_9e79 {
  strings:
    $key_9e79 = { c9 0b [2] fb 29 [2] fd 1c [2] d3 1c [2] ec 00 }

  condition:
    any of them
}