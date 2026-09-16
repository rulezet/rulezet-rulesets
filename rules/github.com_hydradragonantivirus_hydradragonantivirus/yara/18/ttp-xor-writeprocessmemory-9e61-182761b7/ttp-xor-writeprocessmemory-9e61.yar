rule TTP_XOR_WriteProcessMemory_9e61 {
  strings:
    $key_9e61 = { c9 13 [2] fb 31 [2] fd 04 [2] d3 04 [2] ec 18 }

  condition:
    any of them
}